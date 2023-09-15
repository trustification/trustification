use std::net::{IpAddr, TcpListener};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use anyhow::Context;
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

use collector_client::CollectPackagesRequest;
use collectorist_client::{CollectorConfig, Interest};
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::CollectorSnyk;
use trustification_infrastructure::{new_auth, MainContext};
use v11y_client::Vulnerability;

use crate::client::SnykClient;
use crate::{AppState, SharedState};

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    tags(
        (name = "collector-snyk")
    ),
    paths(
        crate::server::collect_packages,
    )
)]
pub struct ApiDoc;

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Configuration error")]
    Configuration,

    #[display(fmt = "GUAC error")]
    GuacError,

    #[display(fmt = "Snyk error")]
    SnykError,

    #[display(fmt = "Internal error")]
    InternalError,
}

impl ResponseError for Error {}

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorSnyk>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind((IpAddr::from_str(&http.bind_addr)?, *http.bind_port))?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);
    log::info!("collectorist at {}", state.collectorist_client.register_collector_url());

    state.addr.write().await.replace(addr);

    HttpServerBuilder::try_from(http)?
        .authorizer(authorizer)
        .metrics(context.metrics.registry().clone(), "collector_snyk")
        .configure(move |svc| {
            svc.app_data(web::Data::from(state.clone()));
            config(svc, authenticator.clone());
        })
        .listen(listener)
        .run()
        .await
}

#[utoipa::path(
    post,
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("packages")]
pub async fn collect_packages(
    request: web::Json<CollectPackagesRequest>,
    state: web::Data<SharedState>,
) -> actix_web::Result<impl Responder> {
    let client = SnykClient::new(&state.snyk_org_id, &state.snyk_token);

    let guac_url = state
        .guac_url
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or(Error::Configuration)?;

    let guac = GuacClient::new(guac_url.as_str());

    for purl in &request.purls {
        let mut vulns: Vec<v11y_client::Vulnerability> = Vec::new();

        for issue in client.issues(purl).await.map_err(|_| Error::SnykError)? {
            let issue_vulns: Vec<Vulnerability> = issue.into();
            vulns.extend_from_slice(&issue_vulns)
        }

        if !vulns.is_empty() {
            guac.intrinsic()
                .ingest_package(&PackageUrl::from_str(purl).map_err(|_| Error::InternalError)?.into())
                .await
                .map_err(|_| Error::GuacError)?;

            for vuln in &vulns {
                guac.intrinsic()
                    .ingest_vulnerability(&VulnerabilityInputSpec {
                        r#type: "snyk".to_string(),
                        vulnerability_id: vuln.id.clone(),
                    })
                    .await
                    .map_err(|_| Error::GuacError)?;

                guac.intrinsic()
                    .ingest_certify_vuln(
                        &PackageUrl::from_str(purl).map_err(|_| Error::InternalError)?.into(),
                        &VulnerabilityInputSpec {
                            r#type: "snyk".to_string(),
                            vulnerability_id: vuln.id.clone(),
                        },
                        &ScanMetadataInput {
                            db_uri: "https://api.snyk.io/".to_string(),
                            db_version: "1.0".to_string(),
                            scanner_uri: "https://trustification.io/".to_string(),
                            scanner_version: "1.0".to_string(),
                            time_scanned: Default::default(),
                            origin: "snyk".to_string(),
                            collector: "snyk".to_string(),
                        },
                    )
                    .await
                    .map_err(|_| Error::GuacError)?;

                state.v11y_client.ingest_vulnerability(vuln).await.ok();
            }
        }
    }

    Ok(HttpResponse::Ok().finish())
}

pub fn config(cfg: &mut web::ServiceConfig, auth: Option<Arc<Authenticator>>) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .wrap(Logger::default())
            .wrap(Compress::default())
            .service(collect_packages),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

pub async fn register_with_collectorist(state: SharedState, advertise: Option<Url>) -> anyhow::Result<()> {
    log::info!("Starting collectorist loop - advertise: {advertise:?}");

    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = match &advertise {
                    Some(url) => url.clone(),
                    None => {
                        Url::parse(&format!("http://{addr}/api/v1/")).context("Failed to build advertisement URL")?
                    }
                };
                info!(
                    "registering with collectorist at {} with callback={}",
                    state.collectorist_client.register_collector_url(),
                    url
                );
                match state
                    .collectorist_client
                    .register_collector(CollectorConfig {
                        url,
                        cadence: Default::default(),
                        interests: vec![Interest::Package],
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
    if state.collectorist_client.deregister_collector().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }

    state.connected.store(false, Ordering::Relaxed);
    state.guac_url.write().await.take();
}
