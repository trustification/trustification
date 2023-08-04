use actix_web::error::{ErrorInternalServerError, ErrorUnprocessableEntity};
use actix_web::http::header::ContentType;
use actix_web::{post, web, HttpResponse, Responder};
use collectorist_api::server::collect::CollectRequest;

use crate::package_manager::PackageManager;
// TODO: use crate::request::Request;
use crate::SharedState;

/// Retrieve vulnerabilities for a list of purls
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
    state: web::Data<SharedState>,
    input: web::Json<CollectRequest>,
    // TODO: change the above to the below to better match CRDA?
    // _request: web::Json<Request>,
    package_manager: web::Path<String>, // what's this for?
) -> actix_web::Result<impl Responder> {
    if let Ok(_package_manager) = PackageManager::try_from(package_manager.as_str()) {
        let request = input.into_inner();
        let url = format!("{}api/v1/collect", state.collectorist_url);
        let response = reqwest::Client::new()
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(|e| ErrorInternalServerError(e))?;
        let v = response.text().await.map_err(|e| ErrorUnprocessableEntity(e))?;
        Ok(HttpResponse::Ok().content_type(ContentType::json()).body(v))
    } else {
        Ok(HttpResponse::BadRequest().finish())
    }
}
