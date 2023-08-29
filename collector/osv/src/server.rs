use std::fmt::Debug;
use std::net::{SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use derive_more::Display;
use guac::client::intrinsic::certify_vuln::ScanMetadataInput;
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::GuacClient;
use log::{info, warn};
use packageurl::PackageUrl;
use reqwest::Url;
use tokio::time::sleep;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use collector_client::{
    CollectPackagesRequest, CollectPackagesResponse, CollectVulnerabilitiesRequest, CollectVulnerabilitiesResponse,
};
use collectorist_client::{CollectorConfig, Interest};

use crate::client::schema::Package;
use crate::client::{OsvClient, QueryBatchRequest, QueryPackageRequest};
use crate::SharedState;

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Configuration error")]
    Configuration,

    #[display(fmt = "GUAC error")]
    GuacError,

    #[display(fmt = "OSV error")]
    OsvError,

    #[display(fmt = "Internal error")]
    InternalError,
}

impl ResponseError for Error {}

#[derive(OpenApi)]
#[openapi(paths(crate::server::collect_packages))]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(bind.into())?;
    let addr = listener.local_addr()?;
    log::debug!("listening on {}", addr);

    state.addr.write().await.replace(addr);

    HttpServer::new(move || App::new().app_data(web::Data::new(state.clone())).configure(config))
        .listen(listener)?
        .run()
        .await?;
    Ok(())
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
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
    state: web::Data<SharedState>,
) -> actix_web::Result<impl Responder> {
    let guac_url = state
        .guac_url
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or(Error::Configuration)?;

    let guac = GuacClient::new(guac_url.as_str());
    let request: QueryBatchRequest = (&*request).into();
    //log::debug!("osv request: {}", serde_json::to_string_pretty(&request).unwrap());
    let response = OsvClient::query_batch(request).await.map_err(|_| Error::OsvError)?;

    for entry in &response.results {
        if let Some(vulns) = &entry.vulns {
            if let Package::Purl { purl } = &entry.package {
                guac.intrinsic()
                    .ingest_package(&PackageUrl::from_str(purl).map_err(|_| Error::InternalError)?.into())
                    .await
                    .map_err(|_| Error::GuacError)?;
                for vuln in vulns {
                    guac.intrinsic()
                        //.ingest_vulnerability("osv", &vuln.id)
                        .ingest_vulnerability(&VulnerabilityInputSpec {
                            r#type: "osv".to_string(),
                            vulnerability_id: vuln.id.clone(),
                        })
                        .await
                        .map_err(|_| Error::GuacError)?;
                    guac.intrinsic()
                        .ingest_certify_vuln(
                            &PackageUrl::from_str(purl).map_err(|_| Error::InternalError)?.into(),
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
                        .map_err(|_| Error::GuacError)?;
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
    state: web::Data<SharedState>,
) -> actix_web::Result<impl Responder> {
    let mut vulnerability_ids = Vec::default();

    for vuln_id in &request.vulnerability_ids {
        if let Ok(osv_vuln) = OsvClient::vulns(vuln_id).await {
            vulnerability_ids.push(osv_vuln.id.clone());
            let v11y_vuln = v11y_client::Vulnerability::from(osv_vuln);
            println!("{:?}", v11y_vuln);
            let _result = state.v11y_client.ingest_vulnerability(&v11y_vuln).await;
        }
    }

    let gathered = CollectVulnerabilitiesResponse { vulnerability_ids };

    Ok(HttpResponse::Ok().json(gathered))
}

pub async fn register_with_collectorist(state: SharedState) {
    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = Url::parse(&format!("http://{}:{}/api/v1/", addr.ip(), addr.port())).unwrap();
                info!("registering with collectorist at {} with callback={}", state.collectorist_client.register_url(), url);
                match state
                    .collectorist_client
                    .register(CollectorConfig {
                        url,
                        cadence: Default::default(),
                        interests: vec![Interest::Package, Interest::Vulnerability],
                    })
                    .await
                {
                    Ok(response) => {
                        state.guac_url.write().await.replace(response.guac_url);
                        state.connected.store(true, Ordering::Relaxed);
                        info!("successfully registered with collectorist")
                    }
                    Err(e) => {
                        warn!("failed to register with collectorist: {}", e)
                    }
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn deregister_with_collectorist(state: SharedState) {
    if state.collectorist_client.deregister().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }

    state.connected.store(false, Ordering::Relaxed);
    state.guac_url.write().await.take();
}
