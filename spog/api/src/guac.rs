use crate::services::guac::GuacService;
use actix_web::web::ServiceConfig;
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/packages").wrap(new_auth!(auth)).to(get));
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
pub struct GetPackage {
    pub purl: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/packages",
    responses(
        (status = 200, description = "Package was found"),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("purl" = String, Path, description = "Package URL of the package to fetch information for"),
    )
)]
pub async fn get(
    guac: web::Data<GuacService>,
    web::Query(GetPackage { purl }): web::Query<GetPackage>,
) -> impl Responder {
    // FIXME: this should do something
    HttpResponse::Ok()
}
