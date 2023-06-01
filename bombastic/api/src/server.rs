use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::web::{self, Bytes};
use actix_web::{App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::info;
use trustification_storage::{Object, Storage};

use crate::sbom::SBOM;

struct AppState {
    storage: RwLock<Storage>,
}

type SharedState = Arc<AppState>;

pub async fn run<B: Into<SocketAddr>>(storage: Storage, bind: B, sync_interval: Duration) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(storage);
    let state = Arc::new(AppState { storage });

    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .app_data(web::Data::new(state.clone()))
            .service(web::resource("/healthz").to(health))
            .service(
                web::scope("/api/v1")
                    .route("/sbom", web::get().to(query_sbom))
                    .route("/sbom", web::post().to(publish_sbom)),
            )
    })
    .bind(&addr)?
    .run()
    .await?;
    Ok(())
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get(&key).await {
        Ok(obj) => {
            tracing::trace!("Retrieved object compressed: {}", obj.compressed);
            if obj.compressed {
                let mut out = Vec::new();
                match ::zstd::stream::copy_decode(&obj.data[..], &mut out) {
                    Ok(_) => HttpResponse::Ok().body(out),
                    Err(_) => HttpResponse::InternalServerError().body("Unable to decode object"),
                }
            } else {
                HttpResponse::Ok().body(obj.data)
            }
        }
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

async fn publish_sbom(state: web::Data<SharedState>, params: web::Query<PublishParams>, data: Bytes) -> HttpResponse {
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

                let mut out = Vec::new();
                let (data, compressed) = match zstd::stream::copy_encode(sbom.raw(), &mut out, 3) {
                    Ok(_) => (&out[..], true),
                    Err(_) => (sbom.raw(), false),
                };
                tracing::debug!("Storing new SBOM ({}), compressed: {}", purl, compressed);
                let annotations = std::collections::HashMap::new();
                let value = Object::new(&purl, annotations, data, compressed);
                match storage.put(&purl, value).await {
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
