use actix_web::{web, web::ServiceConfig, HttpResponse, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use http::header;
use log::{info, trace, warn};
use spog_model::search::{AdvisorySummary, SearchResult};
use std::sync::Arc;
use trustification_api::search::SearchOptions;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

use crate::{search::QueryParams, server::SharedState};

const MAX_LIMIT: usize = 1_000;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/advisory/search")
                .wrap(new_auth!(auth))
                .to(search),
        );
        config.service(web::resource("/api/v1/advisory").to(get));
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct GetParams {
    pub id: String,
    pub token: Option<String>,
}

#[utoipa::path(
    get,
    path = "/public/api/v1/advisory",
    responses(
        (status = 200, description = "Advisory was found"),
        (status = NOT_FOUND, description = "Advisory was not found")
    ),
    params(
        ("id" = String, Path, description = "Id of advisory to fetch"),
    )
)]
pub async fn get(
    state: web::Data<SharedState>,
    web::Query(GetParams { token, id }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> impl Responder {
    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    match state.get_vex(&id, &token).await {
        Ok(stream) => {
            // TODO: should check the content type, but assume JSON for now
            let value = format!(r#"attachment; filename="{}.json""#, id);
            HttpResponse::Ok()
                .append_header((header::CONTENT_DISPOSITION, value))
                .streaming(stream)
        }
        Err(e) => {
            warn!("Unable to locate object with key {}: {:?}", id, e);
            HttpResponse::NotFound().finish()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/advisory/search",
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
    params: web::Query<QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
) -> impl Responder {
    let params = params.into_inner();
    trace!("Querying VEX using {}", params.q);
    let result = state
        .search_vex(
            &params.q,
            params.offset,
            params.limit.min(MAX_LIMIT),
            options.into_inner(),
            &access_token,
        )
        .await;

    let result = match result {
        Err(e) => {
            info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    let mut m = Vec::with_capacity(result.result.len());
    for item in result.result {
        let metadata = item.metadata.unwrap_or_default();
        let item = item.document;
        m.push(AdvisorySummary {
            id: item.advisory_id.clone(),
            title: item.advisory_title,
            snippet: item.advisory_snippet,
            desc: item.advisory_desc,
            date: item.advisory_date,
            severity: item.advisory_severity,
            cvss_max: item.cvss_max,
            href: format!("/api/v1/advisory?id={}", item.advisory_id),
            cves: item.cves,
            metadata,
        });
    }

    HttpResponse::Ok().json(SearchResult::<Vec<AdvisorySummary>> {
        total: Some(result.total),
        result: m,
    })
}
