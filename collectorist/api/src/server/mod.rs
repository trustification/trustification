use std::net::SocketAddr;

use actix_web::{
    middleware::{Compress, Logger},
    web, App, HttpServer,
};
use derive_more::{Display, Error, From};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::server::collector::{collector_config, deregister_collector, register_collector};
use crate::SharedState;

pub mod collect;
pub mod collector;

#[derive(OpenApi)]
#[openapi(paths(
    crate::server::collector::register_collector,
    crate::server::collector::deregister_collector,
    crate::server::collect::collect,
))]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let addr = bind.into();
    log::info!("listening on {}", addr);
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
            .service(register_collector)
            .service(deregister_collector)
            .service(collector_config)
            .service(collect::collect),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

#[derive(Debug, Display, Error, From)]
enum Error {}
