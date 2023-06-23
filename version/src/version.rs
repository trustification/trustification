use super::*;
use actix_web::{
    get,
    web::{self, ServiceConfig},
    HttpResponse,
};

#[utoipa::path(
    responses(
        (status = 200, description = "Get version information", body = VersionInformation),
    ),
)]
#[get("/.well-known/trustification/version")]
pub async fn version_fn(version: web::Data<VersionInformation>) -> HttpResponse {
    HttpResponse::Ok().json(version)
}

/// configure an endpoint for version information
///
/// As the version information must be generated inside the crate, it must be passed to this
/// function.
pub fn configure(version: VersionInformation, config: &mut ServiceConfig) {
    config.app_data(web::Data::new(version)).service(version_fn);
}

/// Create a service configurator for mounting the version endpoint.
///
/// As the version information will be generated during built time, it must be generated inside
/// the actual crate and not this helper crate. Therefore, we need a macro and pass the value
/// to this function.
///
/// ## Example
///
/// ```ignore
/// use trustification_version::version;
///
/// actix_web::App::new()
///    // ...
///    .configure(version::configurator(version!()));
/// ```
pub fn configurator(version: VersionInformation) -> impl FnOnce(&mut ServiceConfig) {
    move |service| configure(version, service)
}
