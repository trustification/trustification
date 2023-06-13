use std::{
    io::{self},
    net::SocketAddr,
};

use actix_web::{
    error::PayloadError,
    guard,
    http::header::{self, Accept, AcceptEncoding, ContentType, HeaderValue, CONTENT_ENCODING},
    middleware::{Compress, Logger},
    web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use bombastic_model::prelude::*;
use futures::TryStreamExt;
use serde::Deserialize;
use tracing::info;
use trustification_storage::Storage;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{sbom::SBOM, SharedState};

#[derive(OpenApi)]
#[openapi(paths(query_sbom, publish_sbom, search_sbom))]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let openapi = ApiDoc::openapi();

    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .app_data(web::Data::new(state.clone()))
            .service(
                web::scope("/api/v1")
                    .route("/sbom", web::get().to(query_sbom))
                    .route("/sbom/search", web::get().to(search_sbom))
                    .route(
                        "/sbom",
                        web::post()
                            .guard(guard::Header("transfer-encoding", "chunked"))
                            .to(publish_large_sbom),
                    )
                    .route("/sbom", web::post().to(publish_sbom)),
            )
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

// Return decoded stream, unless user's accept-encoding matches our stored encoding
async fn fetch_object(storage: &Storage, key: &str, accept_encoding: AcceptEncoding) -> HttpResponse {
    let encoding = match storage.get_head(key).await {
        Ok(head) if head.status.is_success() => head.content_encoding.and_then(|ref e| {
            accept_encoding
                .negotiate(vec![e.parse().unwrap()].iter())
                .map(|s| s.to_string())
                .filter(|x| x == e)
        }),
        _ => {
            return HttpResponse::NotFound().finish();
        }
    };
    match encoding {
        Some(enc) => match storage.get_encoded_stream(key).await {
            Ok(stream) => HttpResponse::Ok()
                .content_type(ContentType::json())
                .insert_header((header::CONTENT_ENCODING, enc))
                .streaming(stream),
            Err(e) => {
                tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
                HttpResponse::NotFound().finish()
            }
        },
        None => match storage.get_stream(key).await {
            Ok(stream) => HttpResponse::Ok().content_type(ContentType::json()).streaming(stream),
            Err(e) => {
                tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
                HttpResponse::NotFound().finish()
            }
        },
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/sbom",
    responses(
        (status = 200, description = "SBOM found"),
        (status = NOT_FOUND, description = "SBOM not found in archive"),
        (status = BAD_REQUEST, description = "Missing valid id or index entry"),
    ),
    params(
        ("id" = String, Query, description = "Package URL or CPE of SBOM to query"),
    )
)]
async fn query_sbom(
    state: web::Data<SharedState>,
    params: web::Query<QueryParams>,
    accept_encoding: web::Header<AcceptEncoding>,
) -> impl Responder {
    let params = params.into_inner();
    if let Some(id) = params.id {
        tracing::trace!("Querying SBOM using id {}", id);
        let storage = state.storage.read().await;
        fetch_object(&storage, &id, accept_encoding.into_inner()).await
    } else {
        HttpResponse::BadRequest().body("Missing valid id")
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
    #[serde(default = "default_offset")]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}

#[utoipa::path(
    get,
    path = "/api/v1/sbom/search",
    responses(
        (status = 200, description = "Search completed"),
        (status = BAD_REQUEST, description = "Bad query"),
    ),
    params(
        ("q" = String, Query, description = "Search query"),
    )
)]
async fn search_sbom(state: web::Data<SharedState>, params: web::Query<SearchParams>) -> impl Responder {
    let params = params.into_inner();

    tracing::info!("Querying SBOM using {}", params.q);

    let index = state.index.read().await;
    let result = index.search(&params.q, params.offset, params.limit);

    let result = match result {
        Err(e) => {
            tracing::info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    HttpResponse::Ok().json(SearchResult {
        total: result.1,
        result: result.0,
    })
}

#[derive(Debug, Deserialize)]
struct PublishParams {
    id: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/sbom",
    responses(
        (status = 200, description = "SBOM found"),
        (status = NOT_FOUND, description = "SBOM not found in archive"),
        (status = BAD_REQUEST, description = "Missing valid id"),
    ),
    params(
        ("id" = String, Query, description = "Package URL or product identifier of SBOM to query"),
    )
)]
async fn publish_sbom(
    state: web::Data<SharedState>,
    params: web::Query<PublishParams>,
    data: web::Bytes,
) -> HttpResponse {
    let params = params.into_inner();
    let storage = state.storage.write().await;
    // TODO: unbuffered I/O
    match SBOM::parse(&data) {
        Ok(sbom) => {
            info!("Valid SBOM");
            let id = params.id;

            tracing::debug!("Storing new SBOM ({id})");
            match storage.put_slice(&id, sbom.raw()).await {
                Ok(_) => {
                    let msg = format!("SBOM of size {} stored successfully", &data[..].len());
                    tracing::trace!(msg);
                    HttpResponse::Created().body(msg)
                }
                Err(e) => {
                    let msg = format!("Error storing SBOM: {:?}", e);
                    tracing::warn!(msg);
                    HttpResponse::InternalServerError().body(msg)
                }
            }
        }
        Err(err) => {
            let msg = format!("No valid SBOM uploaded: {err}");
            tracing::info!(msg);
            HttpResponse::BadRequest().body(msg)
        }
    }
}

async fn publish_large_sbom(
    req: HttpRequest,
    state: web::Data<SharedState>,
    params: web::Query<PublishParams>,
    payload: web::Payload,
    content_type: web::Header<ContentType>,
) -> HttpResponse {
    if let Some(res) = verify_type(content_type.into_inner()) {
        return res;
    }
    let enc = match verify_encoding(req.headers().get(CONTENT_ENCODING)) {
        Ok(v) => v,
        Err(res) => {
            return res;
        }
    };
    let id = &params.id;
    let storage = state.storage.write().await;
    let mut payload = payload.map_err(|e| match e {
        PayloadError::Io(e) => e,
        _ => io::Error::new(io::ErrorKind::Other, e),
    });
    match storage.put_stream(id, enc, &mut payload).await {
        Ok(status) => {
            let msg = format!("SBOM stored with status code: {status}");
            tracing::trace!(msg);
            HttpResponse::Created().body(msg)
        }
        Err(e) => {
            let msg = format!("Error storing SBOM: {:?}", e);
            tracing::warn!(msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

fn verify_type(content_type: ContentType) -> Option<HttpResponse> {
    if content_type == ContentType::json() {
        None
    } else {
        Some(HttpResponse::BadRequest().insert_header(Accept::json()).finish())
    }
}

// bzip2 prevents us from using the ContentEncoding enum
fn verify_encoding(content_encoding: Option<&HeaderValue>) -> Result<Option<&str>, HttpResponse> {
    match content_encoding {
        Some(enc) => match enc.to_str() {
            Ok(v @ ("bzip2" | "zstd")) => Ok(Some(v)),
            Ok(_) => Err(HttpResponse::BadRequest()
                .insert_header(AcceptEncoding(vec!["bzip2".parse().unwrap(), "zstd".parse().unwrap()]))
                .finish()),
            Err(_) => Err(HttpResponse::InternalServerError().finish()),
        },
        None => Ok(None),
    }
}
