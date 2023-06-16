use actix_web::{web, web::ServiceConfig, HttpResponse, Responder};
use spog_model::search::{PackageSummary, SearchResult};
use tracing::{debug, info, trace, warn};

use crate::{search, server::SharedState};

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/package/search").to(search));
        config.service(web::resource("/api/v1/package").to(get));
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct GetParams {
    pub id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/package",
    responses(
        (status = 200, description = "Package was found", body = Pet),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("id" = String, Path, description = "Id of package to fetch"),
    )
)]
pub async fn get(state: web::Data<SharedState>, params: web::Query<GetParams>) -> impl Responder {
    let params = params.into_inner();
    match state.get_sbom(&params.id).await {
        Ok(response) => HttpResponse::Ok().streaming(response),
        Err(e) => {
            warn!("Error lookup in bombastic: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/package/search",
    responses(
        (status = 200, description = "Search was performed successfully", body = Pet),
    ),
    params(
        ("q" = String, Path, description = "Search query"),
        ("offset" = u64, Path, description = "Offset in the search results to return"),
        ("limit" = u64, Path, description = "Max entries returned in the search results"),
    )
)]
pub async fn search(state: web::Data<SharedState>, params: web::Query<search::QueryParams>) -> HttpResponse {
    let params = params.into_inner();
    trace!("Querying SBOM using {}", params.q);
    match state.search_sbom(&params.q, params.offset, params.limit).await {
        Ok(mut data) => {
            let mut m: Vec<PackageSummary> = Vec::new();
            for item in data.result.drain(..) {
                m.push(PackageSummary {
                    id: item.id.clone(),
                    purl: item.purl,
                    name: item.name,
                    cpe: item.cpe,
                    version: item.version,
                    sha256: item.sha256,
                    license: item.license,
                    snippet: item.snippet,
                    classifier: item.classifier,
                    supplier: item.supplier.trim_start_matches("Organization: ").to_string(),
                    href: format!("/api/v1/package?id={}", item.id),
                    description: item.description,
                    dependencies: item.dependencies,
                    advisories: Vec::new(),
                });
            }

            let mut result = SearchResult::<Vec<PackageSummary>> {
                total: Some(data.total),
                result: m,
            };

            // TODO: Use guac to lookup advisories for each package!
            search_advisories(state, &mut result.result).await;
            debug!("Search result: {:?}", result);
            HttpResponse::Ok().json(result)
        }
        Err(e) => {
            warn!("Error querying bombastic: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn search_advisories(state: web::Data<SharedState>, packages: &mut Vec<PackageSummary>) {
    for package in packages {
        let q = format!("fixed:\"{}\"", package.name);
        if let Ok(result) = state.search_vex(&q, 0, 1000).await {
            for summary in result.result {
                package.advisories.push(summary.advisory_id);
            }
        }
        info!(
            "Found {} advisories related to {}",
            package.advisories.len(),
            package.purl
        );
    }
}
