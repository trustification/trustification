use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

use crate::SharedState;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectRequest {
    pub(crate) purls: Vec<String>,
}

/// Post a list of purls to be "gathered"
#[utoipa::path(
    post,
    tag = "collectorist",
    path = "/api/v1/collect",
    responses(
        (status = 200, description = "Purls gathered"),
        (status = BAD_REQUEST, description = "Malformed input"),
    ),
)]
#[post("/collect")]
pub(crate) async fn collect(
    state: web::Data<SharedState>,
    input: web::Json<CollectRequest>,
) -> actix_web::Result<impl Responder> {
    let purls = input.into_inner();
    let result = state.gatherer.gather(state.get_ref().clone(), purls).await;
    Ok(HttpResponse::Ok().json(result))
}
