use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{
    get,
    http::header::{self, ContentType},
    middleware::{Compress, Logger},
    route,
    web::{self, Bytes},
    App, HttpResponse, HttpServer, Responder,
};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use trustification_storage::Storage;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use vexination_model::prelude::*;

use crate::SharedState;

#[derive(OpenApi)]
#[openapi(
    paths(fetch_vex, publish_vex, search_vex),
    components(schemas(SearchDocument, SearchResult),)
)]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let openapi = ApiDoc::openapi();
    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .app_data(web::Data::new(state.clone()))
            .service(
                web::scope("/api/v1")
                    .service(fetch_vex)
                    .service(publish_vex)
                    .service(search_vex),
            )
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get_decoded_stream(key).await {
        Ok(stream) => HttpResponse::Ok().content_type(ContentType::json()).streaming(stream),
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            HttpResponse::NotFound().finish()
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
async fn fetch_vex(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> HttpResponse {
    let storage = state.storage.read().await;
    fetch_object(&storage, &params.advisory).await
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
    responses(
        (status = 200, description = "VEX uploaded successfully"),
        (status = BAD_REQUEST, description = "Missing valid id"),
    ),
    params(
        ("advisory" = String, Query, description = "Identifier assigned to the VEX"),
    )
)]
#[route("/vex", method = "PUT", method = "POST")]
async fn publish_vex(state: web::Data<SharedState>, params: web::Query<PublishParams>, data: Bytes) -> HttpResponse {
    let params = params.into_inner();
    let advisory = if let Some(advisory) = params.advisory {
        advisory.to_string()
    } else {
        match serde_json::from_slice::<csaf::Csaf>(&data) {
            Ok(data) => data.document.tracking.id,
            Err(e) => {
                tracing::warn!("Unknown input format: {:?}", e);
                return HttpResponse::BadRequest().into();
            }
        }
    };

    let storage = state.storage.write().await;
    tracing::debug!("Storing new VEX with id: {advisory}");
    match storage.put_json_slice(&advisory, &data).await {
        Ok(_) => {
            let msg = format!("VEX of size {} stored successfully", &data[..].len());
            tracing::trace!(msg);
            HttpResponse::Created().body(msg)
        }
        Err(e) => {
            let msg = format!("Error storing VEX: {:?}", e);
            tracing::warn!(msg);
            HttpResponse::InternalServerError().body(msg)
        }
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
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
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
async fn search_vex(state: web::Data<SharedState>, params: web::Query<SearchParams>) -> impl Responder {
    let params = params.into_inner();

    tracing::info!("Querying VEX using {}", params.q);

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
