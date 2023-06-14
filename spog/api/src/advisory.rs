use std::collections::HashMap;

use actix_web::{web, web::ServiceConfig, HttpResponse, Responder};
use spog_model::search::{AdvisorySummary, SearchResult};
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
        (status = 200, description = "Advisory was found", body = Csaf),
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
        (status = 200, description = "Search was performed successfully", body = SearchResult<Vec<AdvisorySummary>>),
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

    let mut result = match result {
        Err(e) => {
            info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    // Dedup data
    let mut m: HashMap<String, AdvisorySummary> = HashMap::new();

    for item in result.result.drain(..) {
        if let Some(entry) = m.get_mut(&item.advisory_id) {
            if !entry.cves.contains(&item.cve_id) {
                entry.cves.push(item.cve_id);
            }
        } else {
            m.insert(
                item.advisory_id.clone(),
                AdvisorySummary {
                    id: item.advisory_id.clone(),
                    title: item.advisory_title,
                    snippet: item.advisory_snippet,
                    desc: item.advisory_desc,
                    date: item.advisory_date,
                    href: format!("/api/v1/advisory?id={}", item.advisory_id),
                    cves: vec![item.cve_id],
                },
            );
        }
    }

    HttpResponse::Ok().json(SearchResult::<Vec<AdvisorySummary>> {
        total: Some(result.total),
        result: m.values().cloned().collect(),
    })
}
