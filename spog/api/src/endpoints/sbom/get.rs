use crate::app_state::AppState;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use http::header;
use tracing::instrument;

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct GetParams {
    /// ID of package to fetch
    pub id: String,
    /// Access token to use for authentication
    pub token: Option<String>,
}

/// Get (aka download) an SBOM.
#[utoipa::path(
    get,
    path = "/api/v1/sbom",
    responses(
        (status = OK, description = "SBOM was found"),
        (status = NOT_FOUND, description = "SBOM was not found")
    ),
    params(GetParams)
)]
#[instrument(skip(state, access_token))]
pub async fn get(
    state: web::Data<AppState>,
    web::Query(GetParams { id, token }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    let response = state.get_sbom(&id, &token).await?;
    // TODO: should check the content type, but assume JSON for now
    let value = format!(r#"attachment; filename="{}.json""#, id);
    Ok(HttpResponse::Ok()
        .append_header((header::CONTENT_DISPOSITION, value))
        .streaming(response))
}
