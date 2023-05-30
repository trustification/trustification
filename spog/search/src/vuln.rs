use crate::server::{fetch_object, QueryParams, SharedState};
use actix_web::{web, HttpResponse, Responder};
use vexination_index::Index;

pub async fn search(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    tracing::trace!("Querying VEX using {}", params.q);

    let index = state.index.read().await;
    let result = search_vex(&index, &params.q).await;

    if let Err(e) = &result {
        tracing::info!("Error searching: {:?}", e);
        return HttpResponse::InternalServerError().body(e.to_string());
    }
    let result = result.unwrap();

    let mut ret: Vec<serde_json::Value> = Vec::new();
    let storage = state.storage.read().await;

    for key in result.iter() {
        if let Some(obj) = fetch_object(&storage, &key).await {
            if let Ok(data) = serde_json::from_slice(&obj[..]) {
                ret.push(data);
            }
        }
    }

    HttpResponse::Ok().json(ret)
}

async fn search_vex(index: &Index, q: &str) -> anyhow::Result<Vec<String>> {
    Ok(index.search(q, 0, 10)?)
}
