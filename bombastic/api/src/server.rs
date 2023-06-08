use std::{
    io::{self},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use actix_web::{
    error::PayloadError,
    guard,
    http::header::{self, AcceptEncoding, ContentEncoding, ContentType, Encoding},
    middleware::{Compress, Logger},
    web, App, HttpResponse, HttpServer, Responder,
};
use futures::TryStreamExt;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::info;
use trustification_storage::{Error, Storage};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::sbom::SBOM;

struct AppState {
    storage: RwLock<Storage>,
}

type SharedState = Arc<AppState>;

#[derive(OpenApi)]
#[openapi(paths(query_sbom, publish_sbom,))]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(
    storage: Storage,
    bind: B,
    _sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(storage);
    let state = Arc::new(AppState { storage });
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

async fn fetch_object(storage: &Storage, key: &str, accept_encoding: AcceptEncoding) -> HttpResponse {
    let encoded = match accept_encoding.negotiate(vec![Encoding::zstd()].iter()) {
        Some(Encoding::Known(ContentEncoding::Zstd)) => match storage.get_encoded_stream(key, "zstd").await {
            Ok(stream) => {
                tracing::info!("Returning zstd-encoded stream");
                Some(stream)
            }
            Err(Error::S3(e)) => {
                // probably a 404 so no sense in continuing
                tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
                return HttpResponse::NotFound().finish();
            }
            _ => None, // ignore non-S3 errors
        },
        _ => None, // client won't accept zstd-encoded stream
    };
    match encoded {
        Some(stream) => HttpResponse::Ok()
            .content_type(ContentType::json())
            .insert_header(ContentEncoding::Zstd)
            .streaming(stream),
        None => match storage.get_stream(key).await {
            Ok((Some(encoding), stream)) => HttpResponse::Ok()
                .content_type(ContentType::json())
                .insert_header((header::CONTENT_ENCODING, encoding))
                .streaming(stream),
            Ok((None, stream)) => HttpResponse::Ok().content_type(ContentType::json()).streaming(stream),
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
        (status = BAD_REQUEST, description = "Missing valid purl or index entry"),
    ),
    params(
        ("purl" = String, Query, description = "Package URL of SBOM to query"),
    )
)]
async fn query_sbom(
    state: web::Data<SharedState>,
    params: web::Query<QueryParams>,
    accept_encoding: web::Header<AcceptEncoding>,
) -> impl Responder {
    let params = params.into_inner();
    if let Some(purl) = params.purl {
        tracing::trace!("Querying SBOM using purl {}", purl);
        let storage = state.storage.read().await;
        fetch_object(&storage, &purl, accept_encoding.into_inner()).await
    } else {
        HttpResponse::BadRequest().body("Missing valid purl")
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublishParams {
    purl: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/sbom",
    responses(
        (status = 200, description = "SBOM found"),
        (status = NOT_FOUND, description = "SBOM not found in archive"),
        (status = BAD_REQUEST, description = "Missing valid purl or index entry"),
    ),
    params(
        ("purl" = String, Query, description = "Package URL of SBOM to query"),
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
            info!("Detected SBOM");
            if let Some(purl) = params.purl.or(sbom.purl()) {
                if let Err(err) = packageurl::PackageUrl::from_str(&purl) {
                    let msg = format!("Unable to parse purl: {err}");
                    info!(msg);
                    return HttpResponse::BadRequest().body(msg);
                }

                tracing::debug!("Storing new SBOM ({purl})");
                match storage.put_slice(&purl, sbom.raw()).await {
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
            } else {
                let msg = "No pURL found";
                tracing::info!(msg);
                HttpResponse::BadRequest().body(msg)
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
    state: web::Data<SharedState>,
    params: web::Query<PublishParams>,
    payload: web::Payload,
) -> HttpResponse {
    if let Some(purl) = &params.purl {
        let storage = state.storage.write().await;
        let mut payload = payload.map_err(|e| match e {
            PayloadError::Io(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, e),
        });
        match storage.put_stream(purl, &mut payload).await {
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
    } else {
        let msg = "ERROR: purl query param is required for chunked payloads";
        tracing::info!(msg);
        HttpResponse::BadRequest().body(msg)
    }
}
