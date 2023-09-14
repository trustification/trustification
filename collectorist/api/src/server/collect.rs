use std::collections::HashMap;

use actix_web::{http::header::ContentType, post, web, HttpResponse, Responder};
use collector_client::CollectPackagesResponse;

use collectorist_client::CollectPackagesRequest;
use collectorist_client::CollectVulnerabilitiesRequest;

use crate::state::AppState;

/// Post a list of purls to be "gathered"
#[utoipa::path(
    post,
    tag = "collectorist",
    path = "/api/v1/packages",
    responses(
        (status = 200, description = "Purls gathered"),
        (status = BAD_REQUEST, description = "Malformed input"),
    ),
)]
#[post("/packages")]
pub(crate) async fn collect_packages(
    state: web::Data<AppState>,
    input: web::Json<CollectPackagesRequest>,
) -> actix_web::Result<impl Responder> {
    let purls = input.into_inner();
    let results = state.coordinator.collect_packages(&state, purls).await;
    let mut purls = HashMap::<String, Vec<String>>::new();
    for gr in results {
        for k in gr.purls.keys() {
            purls.insert(k.clone(), gr.purls[k].clone());
        }
    }
    let result = CollectPackagesResponse { purls };
    let pretty = serde_json::to_string_pretty(&result)?;
    Ok(HttpResponse::Ok().content_type(ContentType::json()).body(pretty))
}

#[utoipa::path(
    post,
    tag = "collectorist",
    path = "/api/v1/vulnerabilities",
    responses(
        (status = 200, description = "Vulnerabilities gathered"),
        (status = BAD_REQUEST, description = "Malformed input"),
    ),
)]
#[post("/vulnerabilities")]
pub(crate) async fn collect_vulnerabilities(
    state: web::Data<AppState>,
    input: web::Json<CollectVulnerabilitiesRequest>,
) -> actix_web::Result<impl Responder> {
    let request = input.into_inner();
    state.coordinator.collect_vulnerabilities(&state, request).await;
    Ok(HttpResponse::Ok().finish())
}
