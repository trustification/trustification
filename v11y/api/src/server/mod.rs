use crate::server::vulnerability::ingest_vulnerability;
use actix_web::{web, ResponseError};
use derive_more::{Display, Error, From};
use std::sync::Arc;
use trustification_auth::{
    authenticator::Authenticator,
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc},
};
use trustification_infrastructure::new_auth;
use utoipa::OpenApi;

mod search;
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
        crate::server::search::search_cve,
        //crate::server::vulnerability::get_by_alias,
    ),
    components(
        schemas(
            v11y_model::Vulnerability,
            v11y_model::Affected,
            v11y_model::Range,
            v11y_model::Severity,
            v11y_model::Version,
            v11y_model::ScoreType,
            v11y_model::Reference,
        )
    )
)]
pub struct ApiDoc;

pub fn config(
    cfg: &mut web::ServiceConfig,
    auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
    publish_limit: usize,
) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .service(
                web::resource("/vulnerability")
                    .post(ingest_vulnerability)
                    .app_data(web::PayloadConfig::new(publish_limit))
                    .app_data(web::JsonConfig::default().limit(publish_limit)),
            )
            .service(vulnerability::get_cve)
            .service(search::cve_status)
            .service(search::search_cve),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

#[derive(Debug, Display, From)]
pub enum Error {
    #[display(fmt = "Database error")]
    Db,
    #[display(fmt = "index error: {}", "_0")]
    Index(trustification_index::Error),
}

impl ResponseError for Error {}
