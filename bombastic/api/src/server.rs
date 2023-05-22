use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::web::{self, Bytes};
use actix_web::{App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::info;
use trustification_index::Index;
use trustification_storage::{Object, Storage};

use crate::sbom::SBOM;

struct AppState {
    storage: RwLock<Storage>,
    // TODO: Figure out a way to not lock since we use it read only
    index: Mutex<Index>,
}

type SharedState = Arc<AppState>;

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let data = {
            let storage = self.storage.read().await;
            storage.get_index().await?
        };

        let mut index = self.index.lock().await;
        index.sync(&data[..])?;
        tracing::debug!("Index reloaded");
        Ok(())
    }
}

pub async fn run<B: Into<SocketAddr>>(
    storage: Storage,
    index: Index,
    bind: B,
    sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(storage);
    let index = Mutex::new(index);
    let state = Arc::new(AppState { storage, index });

    let sinker = state.clone();
    tokio::task::spawn(async move {
        loop {
            if sinker.sync_index().await.is_ok() {
                tracing::info!("Initial index synced");
                break;
            } else {
                tracing::warn!("Index not yet available");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        loop {
            if let Err(e) = sinker.sync_index().await {
                tracing::info!("Unable to synchronize index: {:?}", e);
            }
            tokio::time::sleep(sync_interval).await;
        }
    });
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
    let result = if let Some(purl) = params.purl {
        tracing::trace!("Querying SBOM using purl {}", purl);
        Ok(purl)
    } else if let Some(sha256) = params.sha256 {
        tracing::trace!("Querying SBOM using sha256 {}", sha256);
        let mut index = state.index.lock().await;
        let result = index.query_sha256(&sha256).await;
        if let Err(e) = &result {
            tracing::info!("Index entry for SHA256 {} not found: {:?}", sha256, e);
        }
        result
    } else {
        return HttpResponse::BadRequest().body("Missing valid purl or sha256");
    };

    match result {
        Ok(key) => {
            let storage = state.storage.read().await;
            fetch_object(&storage, &key).await
        }
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    purl: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublishParams {
    purl: Option<String>,
    sha256: Option<String>,
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

                if let Some(hash) = params.sha256.or(sbom.sha256()) {
                    let mut out = Vec::new();
                    let (data, compressed) = match zstd::stream::copy_encode(sbom.raw(), &mut out, 3) {
                        Ok(_) => (&out[..], true),
                        Err(_) => (sbom.raw(), false),
                    };
                    tracing::debug!(
                        "Storing new SBOM ({}) with hash: {}, compressed: {}",
                        purl,
                        hash,
                        compressed
                    );
                    if let Ok(hash) = hex::decode(hash) {
                        let value = Object::new(&purl, &hash, data, compressed);
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
                        let msg = "Unable to decode digest";
                        tracing::trace!(msg);
                        HttpResponse::BadRequest().body(msg)
                    }
                } else {
                    let msg = "No SHA256 found";
                    tracing::trace!(msg);
                    HttpResponse::BadRequest().body(msg)
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
