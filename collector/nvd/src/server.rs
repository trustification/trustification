use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;

use crate::AppState;
use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use collector_client::CollectVulnerabilitiesRequest;
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use guac::client::GuacClient;
use trustification_auth::{authenticator::Authenticator, authorizer::Authorizer};
use trustification_collector_common::CollectorState;
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Configuration error")]
    Configuration,

    #[error("GUAC error: {0}")]
    GuacError(#[from] guac::client::Error),

    #[error("NVD error: {0}")]
    NvdError(#[source] reqwest::Error),
}

impl ResponseError for Error {}

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    collector_state: CollectorState,
    http: HttpServerConfig<CollectorNvd>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::from_str(&http.bind_addr)?, *http.bind_port);
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    collector_state.set_addr(addr).await;

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
) -> Result<impl Responder, Error> {
    let guac_url = state
        .guac_url
        .read()
        .await
        .as_ref()
        .cloned()
        .ok_or(Error::Configuration)?;

    let guac = GuacClient::new(guac_url.as_str());

    for id in &request.vulnerability_ids {
        if let Some(vuln) = state.nvd.get_cve(id).await.map_err(Error::NvdError)? {
            guac.intrinsic()
                .ingest_vulnerability(&VulnerabilityInputSpec {
                    r#type: "cve".to_string(),
                    vulnerability_id: vuln.cve.id.clone(),
                })
                .await?;

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
