use std::fmt::Debug;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::Ordering;
use std::time::Duration;

use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use derive_more::Display;
use guac::client::certify_vuln::{Metadata, Osv, Vulnerability};
use guac::client::GuacClient;
use log::{info, warn};
use tokio::time::sleep;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use collector_client::{GatherRequest, GatherResponse};
use collectorist_client::CollectorConfig;

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
}

impl ResponseError for Error {}

#[derive(OpenApi)]
#[openapi(paths(crate::server::gather))]
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
            .service(gather),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

impl From<&GatherRequest> for QueryBatchRequest {
    fn from(request: &GatherRequest) -> Self {
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
    path = "/api/v1/gather",
    responses(
	(status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("gather")]
pub async fn gather(
    request: web::Json<GatherRequest>,
    state: web::Data<SharedState>,
) -> actix_web::Result<impl Responder> {
    let guac_url = state
        .guac_url
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or(Error::Configuration)?;

    let guac = GuacClient::new(guac_url);
    let request: QueryBatchRequest = (&*request).into();
    log::debug!("osv request: {}", serde_json::to_string_pretty(&request).unwrap());
    let response = OsvClient::query_batch(request).await.map_err(|_| Error::OsvError)?;

    for entry in &response.results {
        if let Some(vulns) = &entry.vulns {
            if let Package::Purl { purl } = &entry.package {
                guac.ingest_package(purl).await.map_err(|_| Error::GuacError)?;
                for vuln in vulns {
                    guac.ingest_osv(Osv {
                        osv_id: vuln.id.clone(),
                    })
                    .await
                    .map_err(|_| Error::GuacError)?;

                    guac.ingest_certify_vuln(
                        purl,
                        Vulnerability::Osv(Osv {
                            osv_id: vuln.id.clone(),
                        }),
                        Metadata {
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
    let gathered = GatherResponse::from(response);
    log::debug!("osv response: {}", serde_json::to_string_pretty(&gathered).unwrap());
    Ok(HttpResponse::Ok().json(gathered))
}

pub async fn register_with_collectorist(state: SharedState) {
    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = format!("http://{}:{}/api/v1/gather", addr.ip(), addr.port());
                info!("registering with collectorist: callback={}", url);
                if let Ok(response) = state
                    .client
                    .register(CollectorConfig {
                        url,
                        cadence: Default::default(),
                    })
                    .await
                {
                    state.guac_url.write().await.replace(response.guac_url);
                    state.connected.store(true, Ordering::Relaxed);
                    info!("successfully registered with collectorist")
                } else {
                    warn!("failed to register with collectorist")
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn deregister_with_collectorist(state: SharedState) {
    if state.client.deregister().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }

    state.connected.store(false, Ordering::Relaxed);
    state.guac_url.write().await.take();
}
