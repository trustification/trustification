use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::{guard, web, App, HttpResponse, HttpServer, Responder};
use bombastic_index::Index;
use futures::TryStreamExt;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tokio_util::io::StreamReader;
use tracing::info;
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
            .app_data(web::Data::new(state.clone()))
            .service(web::resource("/healthz").to(health))
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

#[derive(Debug, Deserialize)]
struct PublishLargeParams {
    purl: String,
    sha256: String,
}

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
                    let mut annotations = std::collections::HashMap::new();
                    annotations.insert("digest", hash.as_str());
                    let value = Object::new(&purl, annotations, Some(data), compressed);
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

async fn publish_large_sbom(
    state: web::Data<SharedState>,
    params: web::Query<PublishLargeParams>,
    payload: web::Payload,
) -> HttpResponse {
    let storage = state.storage.write().await;
    let mut annotations = std::collections::HashMap::new();
    annotations.insert("digest", params.sha256.as_str());
    let value = Object::new(&params.purl, annotations, None, false);
    let mut reader = StreamReader::new(payload.map_err(|e| io::Error::new(io::ErrorKind::Other, e)));
    match storage.put_stream(&params.purl, value, &mut reader).await {
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
