use actix_web::{web, web::ServiceConfig, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::Bytes;
use http::header;
use log::trace;
use spog_model::search::AdvisorySummary;
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::{SearchOptions, SearchResult};
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::{app_state::AppState, search::QueryParams};

const MAX_LIMIT: usize = 1_000;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/advisory/search")
                .wrap(new_auth!(auth))
                .to(search),
        );
        // the get operation doesn't get the authenticator added, as we check this using the access_token query parameter
        config.service(web::resource("/api/v1/advisory").to(get));
        config.service(web::resource("/api/v1/advisory/upload").to(post));
    }
}

#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct GetParams {
    /// ID of the advisory/VEX to retrieve
    pub id: String,
    /// The bearer token
    pub token: Option<String>,
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct PostParams {
    /// Access token to use for authentication
    pub token: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/advisory",
    responses(
        (status = OK, description = "Advisory was found"),
        (status = NOT_FOUND, description = "Advisory was not found")
    ),
    params(GetParams)
)]
#[instrument(skip(state, access_token), err)]
pub async fn get(
    state: web::Data<AppState>,
    web::Query(GetParams { token, id }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    let stream = state.get_vex(&id, &token).await?;
    // TODO: should check the content type, but assume JSON for now
    let value = format!(r#"attachment; filename="{}.json""#, id);
    Ok(HttpResponse::Ok()
        .append_header((header::CONTENT_DISPOSITION, value))
        .streaming(stream))
}

#[utoipa::path(
    post,
    path = "/api/v1/advisory",
    responses(
        (status = OK, description = "Advisory was uploaded")
    ),
    params(GetParams)
)]
#[instrument(skip(state, access_token), err)]
pub async fn post(
    data: Bytes,
    state: web::Data<AppState>,
    web::Query(crate::endpoints::sbom::PostParams { token }): web::Query<crate::endpoints::sbom::PostParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();

    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    state.post_vex(&id, &token, data).await?;
    Ok(HttpResponse::Ok().body(id))
}

#[utoipa::path(
    get,
    path = "/api/v1/advisory/search",
    responses(
        (status = OK, description = "Search was performed successfully", body = SearchResultVex),
    ),
    params(QueryParams, SearchOptions)
)]
#[instrument(skip(state, access_token), err)]
pub async fn search(
    state: web::Data<AppState>,
    params: web::Query<QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
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
        .await?;

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
            cve_severity_count: item.cve_severity_count,
            metadata,
        });
    }

    Ok(HttpResponse::Ok().json(SearchResult::<Vec<AdvisorySummary>> {
        total: Some(result.total),
        result: m,
    }))
}
