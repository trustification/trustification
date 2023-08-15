use std::collections::HashMap;

use actix_web::{http::header::ContentType, post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

use collector_client::{CollectPackagesResponse, VulnerabilityIds};

use crate::SharedState;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectRequest {
    pub(crate) purls: Vec<String>,
}

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
    state: web::Data<SharedState>,
    input: web::Json<CollectRequest>,
) -> actix_web::Result<impl Responder> {
    let purls = input.into_inner();
    let results = state.coordinator.collect_packages(state.get_ref().clone(), purls).await;
    let mut purls = HashMap::<String, VulnerabilityIds>::new();
    for gr in results {
        for k in gr.purls.keys() {
            purls.insert(k.clone(), gr.purls[k].clone());
        }
    }
    let result = CollectPackagesResponse { purls };
    let pretty = serde_json::to_string_pretty(&result)?;
    Ok(HttpResponse::Ok().content_type(ContentType::json()).body(pretty))
}
