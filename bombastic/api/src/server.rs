use std::io::{self};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::error::PayloadError;
use actix_web::http::header::ContentType;
use actix_web::middleware::Logger;
use actix_web::{guard, web, App, HttpResponse, HttpServer, Responder};
use futures::TryStreamExt;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::info;
use trustification_storage::Storage;

use crate::sbom::SBOM;

struct AppState {
    storage: RwLock<Storage>,
}

type SharedState = Arc<AppState>;

pub async fn run<B: Into<SocketAddr>>(
    storage: Storage,
    bind: B,
    _sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(storage);
    let state = Arc::new(AppState { storage });

    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
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
    })
    .bind(&addr)?
    .run()
    .await?;
    Ok(())
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get_stream(key).await {
        Ok((Some(ctype), stream)) => HttpResponse::Ok().content_type(ctype).streaming(stream),
        Ok((None, stream)) => HttpResponse::Ok().streaming(stream),
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            HttpResponse::NotFound().finish()
        }
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn query_sbom(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    if let Some(purl) = params.purl {
        tracing::trace!("Querying SBOM using purl {}", purl);
        let storage = state.storage.read().await;
        fetch_object(&storage, &purl).await
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

async fn publish_sbom(
    state: web::Data<SharedState>,
    params: web::Query<PublishParams>,
    data: web::Bytes,
    content_type: web::Header<ContentType>,
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
                let mime = content_type.into_inner().0;
                match storage.put_slice(&purl, mime, &mut sbom.raw()).await {
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
    content_type: web::Header<ContentType>,
) -> HttpResponse {
    if let Some(purl) = &params.purl {
        let storage = state.storage.write().await;
        let mut payload = payload.map_err(|e| match e {
            PayloadError::Io(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, e),
        });
        let mime = content_type.into_inner().0;
        match storage.put_stream(&purl, mime, &mut payload).await {
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
        return HttpResponse::BadRequest().body(msg);
    }
}
