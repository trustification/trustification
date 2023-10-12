use actix_web::{
    get,
    web::{self, ServiceConfig},
    HttpResponse,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Endpoints {
    pub vexination: String,
    pub bombastic: String,
}

pub fn configurator(endpoints: Endpoints) -> impl FnOnce(&mut ServiceConfig) {
    move |service| configure(endpoints, service)
}

pub fn configure(endpoints: Endpoints, config: &mut ServiceConfig) {
    config.app_data(web::Data::new(endpoints)).service(endpoints_fn);
}

#[utoipa::path(
    responses(
        (status = 200, description = "Get endpoints", body = Endpoints),
    ),
)]
#[get("/.well-known/trustification/endpoints")]
pub async fn endpoints_fn(endpoints: web::Data<Endpoints>) -> HttpResponse {
    HttpResponse::Ok().json(endpoints)
}
