use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use collector_client::{CollectVulnerabilitiesRequest, CollectVulnerabilitiesResponse};
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;
use tracing::instrument;
use trustification_auth::{authenticator::Authenticator, authorizer::Authorizer};
use trustification_infrastructure::{
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::CollectorNvd,
    new_auth, MainContext,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::AppState;

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
    #[error("GUAC error: {0}")]
    GuacError(#[from] guac::client::Error),

    #[error("NVD error: {0}")]
    #[allow(unused)]
    NvdError(#[source] reqwest::Error),
}

impl ResponseError for Error {}

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorNvd>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::from_str(&http.bind_addr)?, *http.bind_port);
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

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
#[instrument(skip(state), err)]
pub async fn collect_vulnerabilities(
    request: web::Json<CollectVulnerabilitiesRequest>,
    state: web::Data<AppState>,
) -> Result<impl Responder, Error> {
    let mut vulnerability_ids = Vec::with_capacity(request.vulnerability_ids.len());
    let mut errors = vec![];

    for id in request.into_inner().vulnerability_ids {
        match state.nvd.get_cve(&id).await {
            Ok(Some(vuln)) => {
                vulnerability_ids.push(id);
                state
                    .guac_client
                    .intrinsic()
                    .ingest_vulnerability(&VulnerabilityInputSpec {
                        r#type: "cve".to_string(),
                        vulnerability_id: vuln.cve.id.clone(),
                    })
                    .await?;

                state.v11y_client.ingest_vulnerability(&(vuln.into())).await.ok();
            }
            Ok(None) => {}
            Err(err) => {
                errors.push(err.to_string());
            }
        }
    }

    let gathered = CollectVulnerabilitiesResponse {
        vulnerability_ids,
        errors,
    };

    Ok(HttpResponse::Ok().json(gathered))
}

pub fn config(cfg: &mut web::ServiceConfig, auth: Option<Arc<Authenticator>>) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .service(collect_vulnerabilities),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}
