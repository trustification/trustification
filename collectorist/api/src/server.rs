use std::net::SocketAddr;

use actix_web::{
    middleware::{Compress, Logger},
    web, App, HttpServer,
};
use derive_more::{Display, Error, From};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::SharedState;

#[derive(OpenApi)]
#[openapi(paths())]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let openapi = ApiDoc::openapi();

    let addr = bind.into();
    log::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .app_data(web::Data::new(state.clone()))
            //.service(web::scope("/api/v1").service(crate::component_analysis::component_analysis))
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

#[derive(Debug, Display, Error, From)]
enum Error {}
