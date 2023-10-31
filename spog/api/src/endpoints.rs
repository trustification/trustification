use actix_web::{
    get,
    web::{self, ServiceConfig},
    HttpResponse,
};
use tracing::instrument;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Endpoints {
    pub vexination: String,
    pub bombastic: String,
    pub collectorist: String,
    pub v11y: String,
}

pub fn configurator(endpoints: Endpoints) -> impl FnOnce(&mut ServiceConfig) {
    move |service| configure(endpoints, service)
}

pub fn configure(endpoints: Endpoints, config: &mut ServiceConfig) {
    config.app_data(web::Data::new(endpoints)).service(endpoints_fn);
}

#[utoipa::path(
    tag = "well-known",
    responses(
        (status = 200, description = "Get endpoints", body = inline(Endpoints)),
    ),
)]
#[get("/.well-known/trustification/endpoints")]
#[instrument(skip_all)]
pub async fn endpoints_fn(endpoints: web::Data<Endpoints>) -> HttpResponse {
    HttpResponse::Ok().json(endpoints)
}
