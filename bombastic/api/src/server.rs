use std::{
    io::{self},
    net::SocketAddr,
};

use crate::SharedState;
use actix_web::{
    delete,
    error::{self, PayloadError},
    get,
    http::{
        header::{self, Accept, AcceptEncoding, ContentType, HeaderValue, CONTENT_ENCODING},
        StatusCode,
    },
    middleware::{Compress, Logger},
    route, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use bombastic_model::prelude::*;
use derive_more::{Display, Error, From};
use futures::TryStreamExt;
use serde::Deserialize;
use trustification_index::Error as IndexError;
use trustification_storage::Error as StorageError;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(query_sbom, publish_sbom, search_sbom, delete_sbom),
    components(schemas(SearchDocument, SearchResult),)
)]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let openapi = ApiDoc::openapi();

    let addr = bind.into();
    log::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .app_data(web::Data::new(state.clone()))
            .service(
                web::scope("/api/v1")
                    .service(query_sbom)
                    .service(search_sbom)
                    .service(publish_sbom)
                    .service(delete_sbom),
            )
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
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
            e => {
                log::info!("ERROR: {:?}", e);
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
) -> actix_web::Result<impl Responder> {
    let key = params.into_inner().id;
    log::trace!("Querying SBOM using id {}", key);
    let storage = state.storage.read().await;
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
    ),
    params(
        ("q" = String, Query, description = "Search query"),
    )
)]
#[get("/sbom/search")]
async fn search_sbom(
    state: web::Data<SharedState>,
    params: web::Query<SearchParams>,
) -> actix_web::Result<impl Responder> {
    let params = params.into_inner();

    log::info!("Querying SBOM using {}", params.q);

    let index = state.index.read().await;
    let result = index
        .search(&params.q, params.offset, params.limit, params.explain)
        .map_err(Error::Index)?;

    Ok(HttpResponse::Ok().json(SearchResult {
        total: result.1,
        result: result.0,
    }))
}

/// Upload an SBOM with an identifier.
///
/// Clients may split the transfer using multipart uploads. The only supported content type is JSON, but content encoding can be unset, bzip2 or zstd.
#[utoipa::path(
    put,
    tag = "bombastic",
    path = "/api/v1/sbom",
    responses(
        (status = 200, description = "SBOM uploaded successfully"),
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
) -> actix_web::Result<impl Responder> {
    let typ = verify_type(content_type)?;
    let enc = verify_encoding(req.headers().get(CONTENT_ENCODING))?;
    let id = &params.id;
    let storage = state.storage.write().await;
    let mut payload = payload.map_err(|e| match e {
        PayloadError::Io(e) => e,
        _ => io::Error::new(io::ErrorKind::Other, e),
    });
    let size = storage
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
        (status = 204, description = "SBOM deleted"),
        (status = NOT_FOUND, description = "SBOM not found in archive"),
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
) -> actix_web::Result<impl Responder> {
    let params = params.into_inner();
    let id = &params.id;
    log::trace!("Deleting SBOM using id {}", id);
    let storage = state.storage.write().await;

    storage.delete(id).await.map_err(Error::Storage)?;

    Ok(HttpResponse::NoContent().finish())
}
