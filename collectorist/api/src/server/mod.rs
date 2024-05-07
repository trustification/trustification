use crate::server::collector::collector_config;
use actix_web::middleware::{Compress, Logger};
use actix_web::web;
use derive_more::{Display, Error, From};
use std::sync::Arc;
use trustification_auth::{
    authenticator::Authenticator,
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc},
};
use trustification_infrastructure::new_auth;
use utoipa::OpenApi;

pub mod collect;
pub mod collector;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    paths(
        crate::server::collect::collect_packages,
    )
)]
pub struct ApiDoc;

pub fn config(
    cfg: &mut web::ServiceConfig,
    auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
            .wrap(new_auth!(auth))
            .service(collector_config)
            .service(collect::collect_packages),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

#[derive(Debug, Display, Error, From)]
enum Error {}
