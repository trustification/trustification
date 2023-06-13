use std::collections::HashSet;

use actix_web::{web, web::ServiceConfig, HttpResponse, Responder};
use futures::StreamExt;
use serde_json::json;
use tracing::{info, trace, warn};

use crate::{search::QueryParams, server::SharedState};

const MAX_LIMIT: usize = 1_000;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/advisory/search").to(search));
        config.service(web::resource("/api/v1/advisory").to(get));
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct GetParams {
    pub id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/advisory",
    responses(
        (status = 200, description = "Advisory was found", body = Pet),
        (status = NOT_FOUND, description = "Advisory was not found")
    ),
    params(
        ("id" = String, Path, description = "Id of advisory to fetch"),
    )
)]
pub async fn get(state: web::Data<SharedState>, params: web::Query<GetParams>) -> impl Responder {
    match state.get_vex(&params.id).await {
        Ok(stream) => HttpResponse::Ok().streaming(stream),
        Err(e) => {
            warn!("Unable to locate object with key {}: {:?}", params.id, e);
            HttpResponse::NotFound().finish()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/advisory/search",
    responses(
        (status = 200, description = "Search was performed successfully", body = Pet),
    ),
    params(
        ("q" = String, Path, description = "Search query"),
        ("offset" = u64, Path, description = "Offset in the search results to return"),
        ("limit" = u64, Path, description = "Max entries returned in the search results"),
    )
)]
pub async fn search(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    trace!("Querying VEX using {}", params.q);
    let result = state
        .search_vex(&params.q, params.offset, params.limit.min(MAX_LIMIT))
        .await;

    let result = match result {
        Err(e) => {
            info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    let mut ret: Vec<serde_json::Value> = Vec::new();

    // Dedup data
    let mut dedup: HashSet<String> = HashSet::new();

    // TODO: stream these?
    for key in result.result.iter() {
        if !dedup.contains(&key.advisory) {
            if let Ok(mut obj) = state.get_vex(&key.advisory).await {
                let mut data = Vec::new();
                while let Some(item) = obj.next().await {
                    match item {
                        Ok(item) => {
                            data.extend_from_slice(&item[..]);
                        }
                        Err(e) => {
                            warn!("Error consuming object stream: {:?}", e);
                            return HttpResponse::InternalServerError().body(e.to_string());
                        }
                    }
                }
                if let Ok(data) = serde_json::from_slice(&data[..]) {
                    ret.push(data);
                    dedup.insert(key.advisory.clone());
                }
            }
        }
    }

    HttpResponse::Ok().json(json!({
        "result": ret,
        "total": result.total,
    }))
}
