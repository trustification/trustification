use actix_web::web::ServiceConfig;
use actix_web::{web, HttpResponse};
use service::GuacService;
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) mod service;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/packages").wrap(new_auth!(auth.clone())).to(get));
        config.service(
            web::resource("/api/v1/packages/dependencies")
                .wrap(new_auth!(auth.clone()))
                .to(get_dependencies),
        );
        config.service(
            web::resource("/api/v1/packages/dependents")
                .wrap(new_auth!(auth))
                .to(get_dependents),
        );
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
) -> actix_web::Result<HttpResponse> {
    let pkgs = guac.get_packages(&purl).await?;

    Ok(HttpResponse::Ok().json(pkgs))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
pub struct GetDependencies {
    pub purl: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/packages/dependencies",
    responses(
        (status = 200, description = "Package was found"),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("purl" = String, Path, description = "Package URL of the package to fetch information for"),
    )
)]
pub async fn get_dependencies(
    guac: web::Data<GuacService>,
    web::Query(GetDependencies { purl }): web::Query<GetDependencies>,
) -> actix_web::Result<HttpResponse> {
    let deps = guac.get_dependencies(&purl).await?;

    Ok(HttpResponse::Ok().json(deps))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
pub struct GetDependents {
    pub purl: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/packages/dependents",
    responses(
        (status = 200, description = "Package was found"),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("purl" = String, Path, description = "Package URL of the package to fetch information for"),
    )
)]
pub async fn get_dependents(
    guac: web::Data<GuacService>,
    web::Query(GetDependencies { purl }): web::Query<GetDependencies>,
) -> actix_web::Result<HttpResponse> {
    let deps = guac.get_dependents(&purl).await?;

    Ok(HttpResponse::Ok().json(deps))
}
