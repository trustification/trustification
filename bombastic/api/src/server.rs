use std::io::{self};
use std::sync::Arc;

use crate::SharedState;
use actix_web::{
    delete,
    error::{self, PayloadError},
    get,
    http::{
        header::{self, Accept, AcceptEncoding, ContentType, HeaderValue, CONTENT_ENCODING},
        StatusCode,
    },
    middleware::Compress,
    route, web, HttpRequest, HttpResponse, Responder,
};
use bombastic_model::prelude::*;
use derive_more::{Display, Error, From};
use futures::TryStreamExt;
use serde::Deserialize;
use trustification_api::search::SearchOptions;
use trustification_auth::{
    authenticator::{user::UserInformation, Authenticator},
    authorizer::Authorizer,
    swagger_ui::SwaggerUiOidc,
    Permission,
};
use trustification_index::Error as IndexError;
use trustification_infrastructure::new_auth;
use trustification_storage::Error as StorageError;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(query_sbom, publish_sbom, search_sbom, delete_sbom),
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
            .wrap(Compress::default())
            .service(query_sbom)
            .service(search_sbom)
            .service(publish_sbom)
            .service(delete_sbom),
    )
    .service({
        let mut openapi = ApiDoc::openapi();
        let mut swagger = SwaggerUi::new("/swagger-ui/{_:.*}");

        if let Some(swagger_ui_oidc) = &swagger_ui_oidc {
            swagger = swagger_ui_oidc.apply(swagger, &mut openapi);
        }

        swagger.url("/openapi.json", openapi)
    });
}

const ACCEPT_ENCODINGS: [&str; 2] = ["bzip2", "zstd"];

#[derive(Debug, Display, Error, From)]
enum Error {
    #[display(fmt = "storage error: {}", "_0")]
    Storage(StorageError),
    #[display(fmt = "index error: {}", "_0")]
    Index(IndexError),
    #[display(fmt = "invalid type, see Accept header")]
    InvalidContentType,
    #[display(fmt = "invalid encoding, see Accept-Encoding header")]
    InvalidContentEncoding,
}

impl error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::plaintext());
        match self {
            Self::InvalidContentType => res.insert_header(Accept::json()),
            Self::InvalidContentEncoding => res.insert_header(AcceptEncoding(
                ACCEPT_ENCODINGS.iter().map(|s| s.parse().unwrap()).collect(),
            )),
            _ => &mut res,
        }
        .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Storage(StorageError::NotFound) => StatusCode::NOT_FOUND,
            Self::InvalidContentType | Self::InvalidContentEncoding => StatusCode::BAD_REQUEST,
            Self::Index(IndexError::QueryParser(_)) => StatusCode::BAD_REQUEST,
            e => {
                log::error!("{e:?}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

/// Parameters to fetch and publish requests.
#[derive(Debug, Deserialize)]
struct IdentifierParams {
    /// Identifier of SBOM
    id: String,
}

/// Retrieve an SBOM using its identifier.
#[utoipa::path(
    get,
    tag = "bombastic",
    path = "/api/v1/sbom",
    responses(
        (status = 200, description = "SBOM found"),
        (status = NOT_FOUND, description = "SBOM not found in archive"),
        (status = BAD_REQUEST, description = "Missing valid id or index entry"),
    ),
    params(
        ("id" = String, Query, description = "Identifier of SBOM to fetch"),
    )
)]
#[get("/sbom")]
async fn query_sbom(
    state: web::Data<SharedState>,
    params: web::Query<IdentifierParams>,
    accept_encoding: web::Header<AcceptEncoding>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let key = params.into_inner().id;
    log::trace!("Querying SBOM using id {}", key);
    let storage = &state.storage;
    // determine the encoding of the stored object, if any
    let encoding = storage.get_head(&key).await.ok().and_then(|head| {
        head.content_encoding.and_then(|ref e| {
            accept_encoding
                .negotiate(vec![e.parse().unwrap()].iter())
                .map(|s| s.to_string())
                .filter(|x| x == e)
        })
    });
    match encoding {
        // if client's accept-encoding includes S3 encoding, return encoded stream
        Some(enc) => Ok(HttpResponse::Ok()
            .content_type(ContentType::json())
            .insert_header((header::CONTENT_ENCODING, enc))
            .streaming(storage.get_encoded_stream(&key).await.map_err(Error::Storage)?)),
        // otherwise, decode the stream
        None => Ok(HttpResponse::Ok()
            .content_type(ContentType::json())
            .streaming(storage.get_decoded_stream(&key).await.map_err(Error::Storage)?)),
    }
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

/// Search for an SBOM using a free form search query.
///
/// See the [documentation](https://docs.trustification.dev/trustification/user/retrieve.html) for a description of the query language.
#[utoipa::path(
    get,
    tag = "bombastic",
    path = "/api/v1/sbom/search",
    responses(
        (status = 200, description = "Search completed"),
        (status = BAD_REQUEST, description = "Bad query"),
        (status = 401, description = "Not authenticated"),
    ),
    params(
        ("q" = String, Query, description = "Search query"),
    )
)]
#[get("/sbom/search")]
async fn search_sbom(
    state: web::Data<SharedState>,
    params: web::Query<SearchParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let params = params.into_inner();

    log::info!("Querying SBOM: '{}'", params.q);

    let (result, total) = actix_web::web::block(move || {
        let index = state.index.blocking_read();
        index.search(&params.q, params.offset, params.limit, (&params).into())
    })
    .await?
    .map_err(Error::Index)?;

    Ok(HttpResponse::Ok().json(SearchResult { total, result }))
}

/// Upload an SBOM with an identifier.
///
/// Clients may split the transfer using multipart uploads. The only supported content type is JSON, but content encoding can be unset, bzip2 or zstd.
#[utoipa::path(
    put,
    tag = "bombastic",
    path = "/api/v1/sbom",
    request_body(content = Value, description = "The SBOM to be uploaded", content_type = "application/json"),
    responses(
        (status = 200, description = "SBOM uploaded successfully"),
        (status = 401, description = "User is not authenticated"),
        (status = 403, description = "User is not allowed to perform operation"),
        (status = BAD_REQUEST, description = "Missing valid id"),
    ),
    params(
        ("id" = String, Query, description = "Identifier assigned to the SBOM"),
    )
)]
#[route("/sbom", method = "PUT", method = "POST")]
async fn publish_sbom(
    req: HttpRequest,
    state: web::Data<SharedState>,
    params: web::Query<IdentifierParams>,
    payload: web::Payload,
    content_type: Option<web::Header<ContentType>>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::CreateSbom)?;

    let typ = verify_type(content_type)?;
    let enc = verify_encoding(req.headers().get(CONTENT_ENCODING))?;
    let id = &params.id;
    let mut payload = payload.map_err(|e| match e {
        PayloadError::Io(e) => e,
        _ => io::Error::new(io::ErrorKind::Other, e),
    });
    let size = state
        .storage
        .put_stream(id, typ.as_ref(), enc, &mut payload)
        .await
        .map_err(Error::Storage)?;
    let msg = format!("Successfully uploaded SBOM: id={id}, size={size}");
    log::info!("{}", msg);
    Ok(HttpResponse::Created().body(msg))
}

fn verify_type(content_type: Option<web::Header<ContentType>>) -> Result<ContentType, Error> {
    if let Some(hdr) = content_type {
        let ct = hdr.into_inner();
        if ct == ContentType::json() {
            return Ok(ct);
        }
    }
    Err(Error::InvalidContentType)
}

// bzip2 prevents us from using the ContentEncoding enum
fn verify_encoding(content_encoding: Option<&HeaderValue>) -> Result<Option<&str>, Error> {
    match content_encoding {
        Some(enc) => match enc.to_str() {
            Ok(v) if ACCEPT_ENCODINGS.contains(&v) => Ok(Some(v)),
            _ => Err(Error::InvalidContentEncoding),
        },
        None => Ok(None),
    }
}

/// Delete an SBOM using its identifier.
#[utoipa::path(
    delete,
    tag = "bombastic",
    path = "/api/v1/sbom",
    responses(
        (status = 204, description = "SBOM either deleted or nonexistent"),
        (status = 401, description = "User is not authenticated"),
        (status = 403, description = "User is not allowed to perform operation"),
        (status = BAD_REQUEST, description = "Missing id"),
    ),
    params(
        ("id" = String, Query, description = "Package URL or product identifier of SBOM to query"),
    )
)]
#[delete("/sbom")]
async fn delete_sbom(
    state: web::Data<SharedState>,
    params: web::Query<IdentifierParams>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::DeleteSbom)?;

    let params = params.into_inner();
    let id = &params.id;
    log::trace!("Deleting SBOM using id {}", id);
    state.storage.delete(id).await.map_err(Error::Storage)?;

    Ok(HttpResponse::NoContent().finish())
}
