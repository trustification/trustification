use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::AppState;
use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use collector_client::CollectVulnerabilitiesRequest;
use collectorist_client::{CollectorConfig, Interest};
use derive_more::Display;
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::GuacClient;
use log::{info, warn};
use reqwest::Url;
use tokio::time::sleep;
use trustification_auth::{authenticator::Authenticator, authorizer::Authorizer};
use trustification_infrastructure::{
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::CollectorNvd,
    new_auth, MainContext,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    tags(
        (name = "collector-nvd")
    ),
    paths(
        crate::server::collect_vulnerabilities,
    )
)]
pub struct ApiDoc;

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Configuration error")]
    Configuration,

    #[display(fmt = "GUAC error")]
    GuacError,

    #[display(fmt = "NVD error")]
    NvdError,
}

impl ResponseError for Error {}

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorNvd>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(&http.bind_addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);
    log::info!("collectorist at {}", state.collectorist_client.register_collector_url());

    state.addr.write().await.replace(addr);

    HttpServerBuilder::try_from(http)?
        .authorizer(authorizer)
        .metrics(context.metrics.registry().clone(), "collector_nvd")
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
        (status = 200, description = "Requested vulnerabilities gathered"),
    ),
)]
#[post("vulnerabilities")]
pub async fn collect_vulnerabilities(
    request: web::Json<CollectVulnerabilitiesRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder> {
    let guac_url = state
        .guac_url
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or(Error::Configuration)?;

    let guac = GuacClient::new(guac_url.as_str());

    for id in &request.vulnerability_ids {
        if let Some(vuln) = state.nvd.get_cve(id).await.map_err(|_| Error::NvdError)? {
            guac.intrinsic()
                .ingest_vulnerability(&VulnerabilityInputSpec {
                    r#type: "cve".to_string(),
                    vulnerability_id: vuln.cve.id.clone(),
                })
                .await
                .map_err(|_| Error::GuacError)?;

            state.v11y_client.ingest_vulnerability(&(vuln.into())).await.ok();
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
            .service(collect_vulnerabilities),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

pub async fn register_with_collectorist(state: &AppState, advertise: Option<Url>) {
    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = advertise
                    .clone()
                    .unwrap_or_else(|| Url::parse(&format!("http://{}:{}/api/v1/", addr.ip(), addr.port())).unwrap());
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
                        interests: vec![Interest::Vulnerability],
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

pub async fn deregister_with_collectorist(state: &AppState) {
    if state.collectorist_client.deregister_collector().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }

    state.connected.store(false, Ordering::Relaxed);
    state.guac_url.write().await.take();
}
