use actix_web::{web, web::ServiceConfig, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use http::header;
use log::{debug, trace, warn};
use spog_model::search::{PackageSummary, SearchResult};
use trustification_api::search::SearchOptions;
use trustification_auth::client::TokenProvider;

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
    pub token: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/package",
    responses(
        (status = 200, description = "Package was found"),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("id" = String, Path, description = "Id of package to fetch"),
    )
)]
pub async fn get(
    state: web::Data<SharedState>,
    web::Query(GetParams { id, token }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> impl Responder {
    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    match state.get_sbom(&id, &token).await {
        Ok(response) => {
            // TODO: should check the content type, but assume JSON for now
            let value = format!(r#"attachment; filename="{}.json""#, id);
            HttpResponse::Ok()
                .append_header((header::CONTENT_DISPOSITION, value))
                .streaming(response)
        }
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
        (status = 200, description = "Search was performed successfully"),
    ),
    params(
        ("q" = String, Path, description = "Search query"),
        ("offset" = u64, Path, description = "Offset in the search results to return"),
        ("limit" = u64, Path, description = "Max entries returned in the search results"),
    )
)]
pub async fn search(
    state: web::Data<SharedState>,
    params: web::Query<search::QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
) -> HttpResponse {
    let params = params.into_inner();
    trace!("Querying SBOM using {}", params.q);
    match state
        .search_sbom(
            &params.q,
            params.offset,
            params.limit,
            options.into_inner(),
            &access_token,
        )
        .await
    {
        Ok(data) => {
            let mut m: Vec<PackageSummary> = Vec::with_capacity(data.result.len());
            for item in data.result {
                let metadata = item.metadata.unwrap_or_default();
                let item = item.document;
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
                    created: item.created,
                    metadata,
                });
            }

            let mut result = SearchResult::<Vec<PackageSummary>> {
                total: Some(data.total),
                result: m,
            };

            // TODO: Use guac to lookup advisories for each package!
            search_advisories(state, &mut result.result, &access_token).await;
            debug!("Search result: {:?}", result);
            HttpResponse::Ok().json(result)
        }
        Err(e) => {
            warn!("Error querying bombastic: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn search_advisories(
    state: web::Data<SharedState>,
    packages: &mut Vec<PackageSummary>,
    provider: &dyn TokenProvider,
) {
    for package in packages {
        let q = format!("fixed:\"{}\"", package.name);
        if let Ok(result) = state.search_vex(&q, 0, 1000, Default::default(), provider).await {
            for summary in result.result {
                let summary = summary.document;
                package.advisories.push(summary.advisory_id);
            }
        }
        debug!(
            "Found {} advisories related to {}",
            package.advisories.len(),
            package.purl
        );
    }
}
