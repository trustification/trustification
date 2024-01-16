use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::Bytes;
use tracing::instrument;
use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct PostParams {
    /// Access token to use for authentication
    pub token: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/sbom/upload",
    responses(
        (status = OK, description = "SBOM was uploaded"),
    ),
    params(PostParams)
)]
#[instrument(skip(state, access_token))]
pub async fn post(
    data: Bytes,
    state: web::Data<AppState>,
    web::Query(PostParams { token }): web::Query<PostParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();

    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    state.post_sbom(&id, &token, data).await?;
    Ok(HttpResponse::Ok().body(id))
}
