use core::str::FromStr;
use std::sync::Arc;

use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use actix_web::http::StatusCode;
use actix_web::web::{Json, ServiceConfig};
use actix_web::{error, get, post, web, HttpResponse};
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
pub use spog_model::pkg::*;
use thiserror::Error;

use crate::guac::Guac;
use crate::sbom::SbomRegistry;
use crate::Snyk;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(get_package);
        config.service(get_packages);
        config.service(search_packages);
        config.service(search_package_dependencies);
        config.service(search_package_dependents);
        config.service(check_sbom);
    }
}

#[derive(serde::Deserialize)]
pub struct PackageQuery {
    purl: Option<String>,
}

pub struct TrustedContent {
    sbom: Arc<SbomRegistry>,
    client: Arc<Guac>,
    snyk: Snyk,
}

impl TrustedContent {
    pub fn new(client: Arc<Guac>, sbom: Arc<SbomRegistry>, snyk: Snyk) -> Self {
        Self { client, snyk, sbom }
    }

    pub async fn search(&self, purl_str: &str) -> Result<Vec<PackageRef>, ApiError> {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            let packages: Vec<PackageRef> = self
                .client
                .get_packages(purl.clone())
                .await
                .map_err(|_| ApiError::InternalError)?;

            Ok(packages)
        } else {
            Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            })
        }
    }

    async fn get_package(&self, purl_str: &str) -> Result<Package, ApiError> {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            // get vulnerabilities from Guac
            let mut vulns = self
                .client
                .get_vulnerabilities(purl_str)
                .await
                .map_err(|_| ApiError::InternalError)?;

            // get vulnerabilities from Snyk
            let mut snyk_vulns = crate::snyk::get_vulnerabilities(self.snyk.clone(), purl_str)
                .await
                .map_err(|_| ApiError::InternalError)?;
            vulns.append(&mut snyk_vulns);

            //get related packages from Guac
            let packages: Vec<PackageRef> = self
                .client
                .get_packages(purl.clone())
                .await
                .map_err(|_| ApiError::InternalError)?;

            let mut exact_match = None;
            for package in packages.iter() {
                if package.purl == purl_str {
                    exact_match.replace(package.clone());
                }
            }

            if exact_match.is_none() {
                return Err(ApiError::PackageNotFound {
                    purl: purl_str.to_string(),
                });
            }

            let p = Package {
                purl: Some(purl.to_string()),
                href: Some(format!("/api/package?purl={}", &urlencoding::encode(&purl.to_string()))),
                snyk: None,
                vulnerabilities: vulns,
                sbom: if self.sbom.exists(&purl.to_string()) {
                    Some(format!(
                        "/api/package/sbom?purl={}",
                        &urlencoding::encode(&purl.to_string())
                    ))
                } else {
                    None
                },
            };
            Ok(p)
        } else {
            Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            })
        }
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "Package found", body = Package),
        (status = NOT_FOUND, description = "Package not found", body = Package, example = json!({
                "error": "Package pkg:rpm/redhat/openssl@1.1.1k-7.el8_9 was not found",
                "status": 404
        })),
        (status = BAD_REQUEST, description = "Invalid package URL"),
        (status = BAD_REQUEST, description = "Missing query argument")
    ),
    params(
        ("purl" = String, Query, description = "Package URL to query"),
    )
)]
#[get("/api/package")]
pub async fn get_package(
    data: web::Data<TrustedContent>,
    query: web::Query<PackageQuery>,
) -> Result<HttpResponse, ApiError> {
    if let Some(purl) = &query.purl {
        let p = data.get_package(purl).await?;
        Ok(HttpResponse::Ok().json(p))
    } else {
        Err(ApiError::MissingQueryArgument)
    }
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<Option<Package>>),
        (status = BAD_REQUEST, description = "Invalid package URLs"),
    ),
)]
#[post("/api/package")]
pub async fn get_packages(data: web::Data<TrustedContent>, body: Json<PackageList>) -> Result<HttpResponse, ApiError> {
    let mut packages: Vec<Option<Package>> = Vec::new();
    for purl in body.list().iter() {
        if let Ok(p) = data.get_package(purl).await {
            packages.push(Some(p));
        }
    }
    Ok(HttpResponse::Ok().json(packages))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<PackageDependencies>),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/dependencies")]
pub async fn search_package_dependencies(
    data: web::Data<Arc<Guac>>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut dependencies: Vec<PackageDependencies> = Vec::new();
    for purl in body.list().iter() {
        if PackageUrl::from_str(purl).is_ok() {
            let lst = data.get_dependencies(purl).await.map_err(|_| ApiError::InternalError)?;
            dependencies.push(lst);
        } else {
            return Err(ApiError::InvalidPackageUrl { purl: purl.to_string() });
        }
    }
    Ok(HttpResponse::Ok().json(dependencies))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<PackageDependents>),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/dependents")]
pub async fn search_package_dependents(
    data: web::Data<Arc<Guac>>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut dependencies: Vec<PackageDependencies> = Vec::new();
    for purl in body.list().iter() {
        if PackageUrl::from_str(purl).is_ok() {
            let lst = data.get_dependents(purl).await.map_err(|_| ApiError::InternalError)?;
            dependencies.push(lst);
        } else {
            return Err(ApiError::InvalidPackageUrl { purl: purl.to_string() });
        }
    }
    Ok(HttpResponse::Ok().json(dependencies))
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "Package found", body = Vec<PackageRef>, example = json!(vec![
            (PackageRef {
                purl: "pkg:maven/io.vertx/vertx-web@4.3.4.redhat-00007".to_string(),
                href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/io.vertx/vertx-web@4.3.4.redhat-00007")),
                sbom: None,
                })]
        )),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[post("/api/package/search")]
pub async fn search_packages(
    data: web::Data<TrustedContent>,
    body: Json<PackageList>,
) -> Result<HttpResponse, ApiError> {
    let mut versions = Vec::new();
    for purl_str in body.list().iter() {
        if PackageUrl::from_str(purl_str).is_ok() {
            versions = data.search(purl_str).await?;
        } else {
            return Err(ApiError::InvalidPackageUrl {
                purl: purl_str.to_string(),
            });
        }
    }
    Ok(HttpResponse::Ok().json(versions))
}

#[derive(serde::Deserialize)]
pub struct SBOMQuery {
    purl: Option<String>,
    #[serde(default)]
    download: bool,
}

#[utoipa::path(
    request_body = PackageList,
    responses(
        (status = 200, description = "SBOM found", body = serde_json::Value),
        (status = BAD_REQUEST, description = "Invalid package URL"),
    ),
)]
#[get("/api/package/sbom")]
pub async fn check_sbom(
    data: web::Data<Arc<SbomRegistry>>,
    query: web::Query<SBOMQuery>,
) -> Result<HttpResponse, ApiError> {
    if let Some(purl) = &query.purl {
        if let Some(value) = data.lookup(purl) {
            let mut response = HttpResponse::Ok();
            if query.download {
                response.append_header(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![
                        // TODO: I guess we can do better, but for now it's ok
                        DispositionParam::Filename("sbom.json".to_string()),
                    ],
                });
            }
            Ok(response.json(value))
        } else {
            Err(ApiError::PackageNotFound { purl: purl.to_string() })
        }
    } else {
        Err(ApiError::MissingQueryArgument)
    }
}

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ApiError {
    #[error("No query argument was specified")]
    MissingQueryArgument,
    #[error("Package {purl} was not found")]
    PackageNotFound { purl: String },
    #[error("{purl} is not a valid package URL")]
    InvalidPackageUrl { purl: String },
    #[error("Error processing error internally")]
    InternalError,
}

impl error::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "status": self.status_code().as_u16(),
            "error": self.to_string(),
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::MissingQueryArgument => StatusCode::BAD_REQUEST,
            ApiError::PackageNotFound { purl: _ } => StatusCode::NOT_FOUND,
            ApiError::InvalidPackageUrl { purl: _ } => StatusCode::BAD_REQUEST,
            ApiError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
