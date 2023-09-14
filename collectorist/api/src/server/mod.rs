use crate::server::collector::{collector_config, deregister_collector, register_collector};
use crate::state::AppState;
use actix_cors::Cors;
use actix_web::{web, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use anyhow::anyhow;
use derive_more::{Display, Error, From};
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

pub mod collect;
pub mod collector;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    paths(
        crate::server::collector::register_collector,
        crate::server::collector::deregister_collector,
        crate::server::collect::collect_packages,
        crate::server::collect::collect_vulnerabilities,
    )
)]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(
    state: Arc<AppState>,
    bind: B,
    metrics: Arc<Metrics>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) -> Result<(), anyhow::Error> {
    let addr = bind.into();
    log::info!("listening on {}", addr);

    let http_metrics = PrometheusMetricsBuilder::new("bombastic_api")
        .registry(metrics.registry().clone())
        .build()
        .map_err(|_| anyhow!("Error registering HTTP metrics"))?;

    HttpServer::new(move || {
        let http_metrics = http_metrics.clone();
        let cors = Cors::permissive();
        let authenticator = authenticator.clone();
        let authorizer = authorizer.clone();
        let swagger_ui_oidc = swagger_ui_oidc.clone();

        new_app(AppOptions {
            cors: Some(cors),
            metrics: Some(http_metrics),
            authenticator: None,
            authorizer,
        })
        .app_data(web::Data::from(state.clone()))
        .configure(|cfg| config(cfg, authenticator, swagger_ui_oidc))
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
            .service(register_collector)
            .service(deregister_collector)
            .service(collector_config)
            .service(collect::collect_packages)
            .service(collect::collect_vulnerabilities),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

#[derive(Debug, Display, Error, From)]
enum Error {}
