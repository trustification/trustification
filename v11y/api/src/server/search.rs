use crate::server::Error;
use crate::AppState;
use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;
use std::sync::Arc;
use trustification_api::search::{SearchOptions, SearchResult};
use trustification_auth::authenticator::user::UserInformation;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::Permission;
use v11y_model::search::StatusResult;

/// Parameters for search query.
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    /// Search query string
    pub q: String,
    /// Offset of documents to return (for pagination)
    #[serde(default = "default_offset")]
    pub offset: usize,
    /// Max number of documents to return
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Provide a detailed explanation of query matches
    #[serde(default = "default_explain")]
    pub explain: bool,
    /// Provide additional metadata from the index
    #[serde(default = "default_metadata")]
    pub metadata: bool,
    /// Enable fetching document summaries
    #[serde(default = "default_summaries")]
    pub summaries: bool,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}

const fn default_explain() -> bool {
    false
}

const fn default_metadata() -> bool {
    false
}

const fn default_summaries() -> bool {
    true
}

impl From<&SearchParams> for SearchOptions {
    fn from(value: &SearchParams) -> Self {
        Self {
            explain: value.explain,
            metadata: value.metadata,
            summaries: value.summaries,
        }
    }
}

/// Search for a CVE using a free form search query.
///
/// See the [documentation](https://docs.trustification.dev/trustification/user/retrieve.html) for a description of the query language.
#[utoipa::path(
    get,
    tag = "cve",
    responses(
        (status = 200, description = "Search completed"),
        (status = BAD_REQUEST, description = "Bad query"),
        (status = 401, description = "Not authenticated"),
    ),
    params(
        ("q" = String, Query, description = "Search query"),
    )
)]
#[get("/search")]
async fn search_cve(
    state: web::Data<AppState>,
    params: web::Query<SearchParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let params = params.into_inner();

    log::debug!("Querying CVE: '{}'", params.q);

    let (result, total) = web::block(move || {
        state
            .index
            .search(&params.q, params.offset, params.limit, (&params).into())
    })
    .await?
    .map_err(|err| {
        log::warn!("Failed to search: {err}");
        err
    })
    .map_err(Error::Index)?;

    Ok(HttpResponse::Ok().json(SearchResult {
        total: Some(total),
        result,
    }))
}

/// Search status of cve using a free form search query.
///
/// See the [documentation](https://docs.trustification.dev/trustification/user/retrieve.html) for a description of the query language.
#[utoipa::path(
    get,
    tag = "cve",
    responses(
    (status = 200, description = "Search completed"),
    (status = BAD_REQUEST, description = "Bad query"),
    (status = 401, description = "Not authenticated"),
    ),
)]
#[get("/status")]
async fn cve_status(
    state: web::Data<AppState>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let state_clone = Arc::clone(&state);

    let (result, _total) = actix_web::web::block(move || {
        state_clone.index.search(
            "-sort:indexedTimestamp",
            0,
            1,
            SearchOptions {
                metadata: false,
                explain: false,
                summaries: true,
            },
        )
    })
    .await?
    .map_err(Error::Index)?;

    let state_clone = Arc::clone(&state);
    let total_docs = actix_web::web::block(move || state_clone.index.get_total_docs())
        .await?
        .map_err(Error::Index)?;

    if let Some(cve) = result.first() {
        Ok(HttpResponse::Ok().json(StatusResult {
            total: Some(total_docs),
            last_updated_cve_id: Some(cve.document.id.to_string()),
            last_updated_date: Some(cve.document.indexed_timestamp),
        }))
    } else {
        Ok(HttpResponse::Ok().json(StatusResult::default()))
    }
}
