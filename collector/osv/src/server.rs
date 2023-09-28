use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use derive_more::Display;
use guac::client::intrinsic::certify_vuln::ScanMetadataInput;
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use packageurl::PackageUrl;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use collector_client::{
    CollectPackagesRequest, CollectPackagesResponse, CollectVulnerabilitiesRequest, CollectVulnerabilitiesResponse,
};
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::CollectorOsv;
use trustification_infrastructure::{new_auth, MainContext};

use crate::{
    client::{schema::Package, QueryBatchRequest, QueryPackageRequest},
    AppState,
};

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "GUAC error")]
    Guac,

    #[display(fmt = "OSV error")]
    Osv,

    #[display(fmt = "Internal error")]
    Internal,
}

impl ResponseError for Error {}

#[derive(OpenApi)]
#[openapi(paths(crate::server::collect_packages, crate::server::collect_vulnerabilities,))]
pub struct ApiDoc;

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorOsv>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::from_str(&http.bind_addr)?, *http.bind_port);
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    HttpServerBuilder::try_from(http)?
        .authorizer(authorizer)
        .metrics(context.metrics.registry().clone(), "collector_osv")
        .configure(move |svc| {
            svc.app_data(web::Data::from(state.clone()));
            config(svc, authenticator.clone());
        })
        .listen(listener)
        .run()
        .await
}

pub fn config(cfg: &mut web::ServiceConfig, auth: Option<Arc<Authenticator>>) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .service(collect_packages)
            .service(collect_vulnerabilities),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

impl From<&CollectPackagesRequest> for QueryBatchRequest {
    fn from(request: &CollectPackagesRequest) -> Self {
        QueryBatchRequest {
            queries: request
                .purls
                .iter()
                .map(|e| QueryPackageRequest {
                    package: Package::Purl { purl: e.clone() },
                })
                .collect(),
        }
    }
}

#[utoipa::path(
    post,
    tag = "collector-osv",
    path = "/api/v1/packages",
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("packages")]
pub async fn collect_packages(
    request: web::Json<CollectPackagesRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, Error> {
    log::info!("-- collect packages");

    let request: QueryBatchRequest = (&*request).into();
    //log::debug!("osv request: {}", serde_json::to_string_pretty(&request).unwrap());
    let response = state.osv.query_batch(request).await.map_err(|_| Error::Osv)?;

    for entry in &response.results {
        log::info!("-- entry");
        if let Some(vulns) = &entry.vulns {
            if let Package::Purl { purl } = &entry.package {
                state
                    .guac_client
                    .intrinsic()
                    .ingest_package(&PackageUrl::from_str(purl).map_err(|_| Error::Internal)?.into())
                    .await
                    .map_err(|_| Error::Guac)?;
                for vuln in vulns {
                    log::info!("ingest vulnerability {} on purl {}", vuln.id, purl);
                    state
                        .guac_client
                        .intrinsic()
                        //.ingest_vulnerability("osv", &vuln.id)
                        .ingest_vulnerability(&VulnerabilityInputSpec {
                            r#type: "osv".to_string(),
                            vulnerability_id: vuln.id.clone(),
                        })
                        .await
                        .map_err(|_| Error::Guac)?;
                    state
                        .guac_client
                        .intrinsic()
                        .ingest_certify_vuln(
                            &PackageUrl::from_str(purl).map_err(|_| Error::Internal)?.into(),
                            &VulnerabilityInputSpec {
                                r#type: "osv".to_string(),
                                vulnerability_id: vuln.id.clone(),
                            },
                            &ScanMetadataInput {
                                db_uri: "https://osv.dev/".to_string(),
                                db_version: "1.0".to_string(),
                                scanner_uri: "https://trustification.io/".to_string(),
                                scanner_version: "1.0".to_string(),
                                time_scanned: Default::default(),
                                origin: "osv".to_string(),
                                collector: "osv".to_string(),
                            },
                        )
                        .await
                        .map_err(|_| Error::Guac)?;
                }
            }
        }
    }
    let gathered = CollectPackagesResponse::from(response);
    log::debug!("osv response: {}", serde_json::to_string_pretty(&gathered).unwrap());
    Ok(HttpResponse::Ok().json(gathered))
}

#[utoipa::path(
    post,
    tag = "collector-osv",
    path = "/api/v1/vulnerabilities",
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("vulnerabilities")]
pub async fn collect_vulnerabilities(
    request: web::Json<CollectVulnerabilitiesRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder> {
    let mut vulnerability_ids = Vec::default();

    for vuln_id in &request.vulnerability_ids {
        match state.osv.vulns(vuln_id).await {
            Ok(Some(osv_vuln)) => {
                vulnerability_ids.push(osv_vuln.id.clone());
                let v11y_vuln = v11y_client::Vulnerability::from(osv_vuln);
                log::debug!("{:?}", v11y_vuln);
                if let Err(err) = state.v11y_client.ingest_vulnerability(&v11y_vuln).await {
                    log::warn!("Failed to store in v11y: {err}");
                }
            }
            Ok(None) => {
                // not found
            }
            Err(err) => {
                log::warn!("Failed to query OSV: {err}");
            }
        }
    }

    let gathered = CollectVulnerabilitiesResponse { vulnerability_ids };

    log::info!("Gathered information: {gathered:?}");

    Ok(HttpResponse::Ok().json(gathered))
}
