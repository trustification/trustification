use std::collections::HashMap;

use actix_web::{http::header::ContentType, post, web, HttpResponse, Responder};
use collector_client::{GatherResponse, Vurls};
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
    let results = state.gatherer.gather(state.get_ref().clone(), purls).await;
    let mut purls = HashMap::<String, Vurls>::new();
    for gr in results {
        for k in gr.purls.keys() {
            purls.insert(k.clone(), gr.purls[k].clone());
        }
    }
    let result = GatherResponse { purls };
    let pretty = serde_json::to_string_pretty(&result)?;
    Ok(HttpResponse::Ok().content_type(ContentType::json()).body(pretty))
}
