use std::net::SocketAddr;

use actix_web::{
    middleware::{Compress, Logger},
    web, App, HttpServer, ResponseError,
};
use derive_more::{Display, Error};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::SharedState;

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

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let addr = bind.into();
    log::debug!("listening on {}", addr);
    HttpServer::new(move || App::new().app_data(web::Data::new(state.clone())).configure(config))
        .bind(addr)?
        .run()
        .await?;
    Ok(())
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
            .service(vulnerability::ingest_vulnerability)
            .service(vulnerability::get),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Database error")]
    Db,
}

impl ResponseError for Error {}
