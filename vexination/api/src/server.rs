use actix_web::{
    delete, get,
    http::header::ContentType,
    http::StatusCode,
    route,
    web::{self, Bytes},
    HttpResponse, Responder,
};
use derive_more::{Display, Error, From};
use serde::Deserialize;
use std::sync::Arc;
use trustification_api::search::SearchOptions;
use trustification_auth::{
    authenticator::{user::UserInformation, Authenticator},
    authorizer::Authorizer,
    swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc},
    Permission,
};
use trustification_index::Error as IndexError;
use trustification_infrastructure::new_auth;
use trustification_storage::{Error as StorageError, Storage};
use utoipa::OpenApi;
use vexination_model::prelude::*;

use crate::SharedState;

#[derive(OpenApi)]
#[openapi(
    paths(fetch_vex, publish_vex, search_vex),
    components(schemas(SearchDocument, SearchResult),)
)]
pub struct ApiDoc;

pub fn config(
    cfg: &mut web::ServiceConfig,
    auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(new_auth!(auth))
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .service(fetch_vex)
            .service(publish_vex)
            .service(search_vex)
            .service(delete_vex),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get_decoded_stream(key).await {
        Ok(stream) => HttpResponse::Ok().content_type(ContentType::json()).streaming(stream),
        Err(e) => {
            log::warn!("Unable to locate object with key {}: {:?}", key, e);
            HttpResponse::NotFound().finish()
        }
    }
}

#[derive(Debug, Display, Error, From)]
enum Error {
    #[display(fmt = "storage error: {}", "_0")]
    Storage(StorageError),
    #[display(fmt = "index error: {}", "_0")]
    Index(IndexError),
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::plaintext());
        res.body(if self.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            "Internal server error".to_string()
        } else {
            self.to_string()
        })
    }
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Storage(StorageError::NotFound) => StatusCode::NOT_FOUND,
            Self::Index(IndexError::QueryParser(_)) => StatusCode::BAD_REQUEST,
            e => {
                log::error!("{e:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

/// Parameters passed when fetching an advisory.
#[derive(Debug, Deserialize)]
struct QueryParams {
    /// Identifier of the advisory to get
    advisory: String,
}

/// Retrieve an SBOM using its identifier.
#[utoipa::path(
    get,
    tag = "vexination",
    path = "/api/v1/vex",
    responses(
        (status = 200, description = "VEX found"),
        (status = NOT_FOUND, description = "VEX not found in archive"),
        (status = BAD_REQUEST, description = "Missing valid id or index entry"),
    ),
    params(
        ("advisory" = String, Query, description = "Identifier of VEX to fetch"),
    )
)]
#[get("/vex")]
async fn fetch_vex(
    state: web::Data<SharedState>,
    params: web::Query<QueryParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<HttpResponse> {
    authorizer.require(&user, Permission::ReadVex)?;

    Ok(fetch_object(&state.storage, &params.advisory).await)
}

/// Parameters passed when publishing advisory.
#[derive(Debug, Deserialize)]
struct PublishParams {
    /// Optional: Advisory identifier (overrides identifier derived from document)
    advisory: Option<String>,
}

/// Upload a VEX document.
///
/// The document must be in the CSAF v2.0 format.
#[utoipa::path(
    put,
    tag = "vexination",
    path = "/api/v1/vex",
    request_body(content = Value, description = "The VEX doc to be uploaded", content_type = "application/json"),
    responses(
        (status = 200, description = "VEX uploaded successfully"),
        (status = BAD_REQUEST, description = "Missing valid id"),
    ),
    params(
        ("advisory" = String, Query, description = "Identifier assigned to the VEX"),
    )
)]
#[route("/vex", method = "PUT", method = "POST")]
async fn publish_vex(
    state: web::Data<SharedState>,
    params: web::Query<PublishParams>,
    data: Bytes,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<HttpResponse> {
    authorizer.require(&user, Permission::CreateVex)?;

    let params = params.into_inner();
    let advisory = if let Some(advisory) = params.advisory {
        advisory.to_string()
    } else {
        match serde_json::from_slice::<csaf::Csaf>(&data) {
            Ok(data) => data.document.tracking.id,
            Err(e) => {
                log::warn!("Unknown input format: {:?}", e);
                return Ok(HttpResponse::BadRequest().into());
            }
        }
    };

    log::debug!("Storing new VEX with id: {advisory}");
    state
        .storage
        .put_json_slice(&advisory, &data)
        .await
        .map_err(Error::Storage)?;
    let msg = format!("VEX of size {} stored successfully", &data[..].len());
    log::trace!("{}", msg);
    Ok(HttpResponse::Created().body(msg))
}

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

/// Search for a VEX using a free form search query.
///
/// See the [documentation](https://docs.trustification.dev/trustification/user/retrieve.html) for a description of the query language.
#[utoipa::path(
    get,
    tag = "vexination",
    path = "/api/v1/vex/search",
    responses(
        (status = 200, description = "Search completed"),
        (status = BAD_REQUEST, description = "Bad query"),
    ),
    params(
        ("q" = String, Query, description = "Search query"),
    )
)]
#[get("/vex/search")]
async fn search_vex(
    state: web::Data<SharedState>,
    params: web::Query<SearchParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<HttpResponse> {
    authorizer.require(&user, Permission::ReadVex)?;

    let params = params.into_inner();

    log::info!("Querying VEX using {}", params.q);

    let (result, total) = web::block(move || {
        state
            .index
            .search(&params.q, params.offset, params.limit, (&params).into())
    })
    .await?
    .map_err(Error::Index)?;
    Ok(HttpResponse::Ok().json(SearchResult { total, result }))
}

/// Delete a VEX doc using its identifier.
#[utoipa::path(
    delete,
    tag = "vexination",
    path = "/api/v1/vex",
    responses(
        (status = 204, description = "VEX either deleted or nonexistent"),
        (status = 401, description = "User is not authenticated"),
        (status = 403, description = "User is not allowed to perform operation"),
        (status = BAD_REQUEST, description = "Missing id"),
    ),
    params(
        ("id" = String, Query, description = "Package URL or product identifier of VEX to query"),
    )
)]
#[delete("/vex")]
async fn delete_vex(
    state: web::Data<SharedState>,
    params: web::Query<QueryParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::DeleteVex)?;

    let params = params.into_inner();
    let id = &params.advisory;
    log::trace!("Deleting VEX using id {}", id);

    state.storage.delete(id).await.map_err(Error::Storage)?;

    Ok(HttpResponse::NoContent().finish())
}
