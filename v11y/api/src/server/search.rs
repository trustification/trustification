use crate::AppState;
use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;

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
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}

/// Search for vulnerabilities
#[utoipa::path(
    responses(
        (status = 200, description = "Successfully searched"),
    ),
)]
#[get("/vulnerability")]
pub(crate) async fn search(
    state: web::Data<AppState>,
    query: web::Query<SearchParams>,
) -> actix_web::Result<impl Responder> {
    // let vuln = state.db.search(query.offset, query.limit).await?;
    Ok(HttpResponse::Ok().json(Vec::<()>::new()))
}
