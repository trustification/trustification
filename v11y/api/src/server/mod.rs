use crate::SharedState;
use actix_cors::Cors;
use actix_web::{
    middleware::{Compress, Logger},
    web, HttpServer, ResponseError,
};
use actix_web_prom::PrometheusMetricsBuilder;
use anyhow::anyhow;
use derive_more::{Display, Error};
use std::net::SocketAddr;
use std::sync::Arc;
use trustification_auth::{
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc},
};
use trustification_infrastructure::{
    app::{new_app, AppOptions},
    new_auth, Metrics,
};
use utoipa::OpenApi;

mod vulnerability;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    tags(
        (name = "v11y")
    ),
    paths(
        crate::server::vulnerability::ingest_vulnerability,
        crate::server::vulnerability::get,
    ),
    components(
        schemas(
            v11y_client::Vulnerability,
            v11y_client::Affected,
            v11y_client::Range,
            v11y_client::Severity,
            v11y_client::Version,
            v11y_client::ScoreType,
            v11y_client::Reference,
        )
    )
)]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(
    state: SharedState,
    bind: B,
    metrics: Arc<Metrics>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    swagger_oidc: Option<Arc<SwaggerUiOidc>>,
) -> Result<(), anyhow::Error> {
    let addr = bind.into();
    log::debug!("listening on {}", addr);

    let http_metrics = PrometheusMetricsBuilder::new("bombastic_api")
        .registry(metrics.registry().clone())
        .build()
        .map_err(|_| anyhow!("Error registering HTTP metrics"))?;

    HttpServer::new(move || {
        let http_metrics = http_metrics.clone();
        let cors = Cors::permissive();
        let authenticator = authenticator.clone();
        let authorizer = authorizer.clone();
        let swagger_oidc = swagger_oidc.clone();

        new_app(AppOptions {
            cors: Some(cors),
            metrics: Some(http_metrics),
            authenticator: None,
            authorizer,
        })
        .app_data(web::Data::new(state.clone()))
        .configure(|cfg| config(cfg, authenticator, swagger_oidc))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

pub fn config(
    cfg: &mut web::ServiceConfig,
    auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .wrap(Logger::default())
            .wrap(Compress::default())
            .service(vulnerability::ingest_vulnerability)
            .service(vulnerability::get),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Database error")]
    Db,
}

impl ResponseError for Error {}
