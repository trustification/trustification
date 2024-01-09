use actix_web::{
    get,
    web::{self, ServiceConfig},
    HttpResponse,
};
use tracing::instrument;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Endpoints {
    pub bombastic: String,
    pub collectorist: String,
    pub v11y: String,
}

pub fn configurator(endpoints_information: Endpoints) -> impl FnOnce(&mut ServiceConfig) {
    move |service| configure(endpoints_information, service)
}

fn configure(endpoints_information: Endpoints, config: &mut ServiceConfig) {
    config
        .app_data(web::Data::new(endpoints_information))
        .service(endpoints);
}

#[utoipa::path(
    responses(
        (status = 200, description = "Get endpoints", body = inline(Endpoints)),
    ),
)]
#[get("/.well-known/trustification/endpoints")]
#[instrument(skip_all)]
pub async fn endpoints(endpoints_information: web::Data<Endpoints>) -> HttpResponse {
    HttpResponse::Ok().json(endpoints_information)
}
