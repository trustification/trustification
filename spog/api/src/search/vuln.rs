use super::{fetch_object, QueryParams, SharedState};
use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use spog_model::search::SearchResult;
use trustification_index::IndexStore;

const MAX_LIMIT: usize = 1_000;

pub async fn search(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    tracing::trace!("Querying VEX using {}", params.q);
    let state = &state.vex;

    let index = state.index.read().await;
    let result = search_vex(&index, &params.q, params.offset, params.limit.min(MAX_LIMIT)).await;

    let result = match result {
        Err(e) => {
            tracing::info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    let mut ret: Vec<serde_json::Value> = Vec::new();
    let storage = state.storage.read().await;

    // TODO: stream these
    for key in result.iter() {
        if let Some(obj) = fetch_object(&storage, &key.0).await {
            if let Ok(data) = serde_json::from_slice(&obj[..]) {
                ret.push(data);
            }
        }
    }

    HttpResponse::Ok().json(json!({
        "result": ret,
        "total": result.total,
    }))
}

async fn search_vex(
    index: &IndexStore<vexination_index::Index>,
    q: &str,
    offset: usize,
    limit: usize,
) -> anyhow::Result<SearchResult<Vec<(String, String)>>> {
    Ok(index.search(q, offset, limit)?.into())
}
