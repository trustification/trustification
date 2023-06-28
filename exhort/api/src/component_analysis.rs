use actix_web::{http::header::ContentType, post, web, HttpResponse, Responder};

use crate::package_manager::PackageManager;
use crate::request::Request;
use crate::SharedState;

/// Retrieve an SBOM using its identifier.
#[utoipa::path(
    get,
    tag = "exhort",
    path = "/api/v1/component-analysis",
    responses(
        (status = 200, description = "Analysis completed"),
        (status = BAD_REQUEST, description = "Invalid package-manager path or request body"),
    ),
)]
#[post("/component-analysis/{package_manager}")]
pub async fn component_analysis(
    _state: web::Data<SharedState>,
    _request: web::Json<Request>,
    package_manager: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    if let Ok(_package_manager) = PackageManager::try_from(package_manager.as_str()) {
        Ok(HttpResponse::Ok().content_type(ContentType::json()).finish())
    } else {
        Ok(HttpResponse::BadRequest().content_type(ContentType::json()).finish())
    }
}
