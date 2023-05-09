use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::Router;
use bombastic_index::Index;
use bombastic_storage::{Object, Storage};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

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

    let app = Router::new()
        .route("/api/v1/sbom", get(query_sbom))
        .route("/api/v1/sbom/:id", get(fetch_sbom))
        .route("/api/v1/sbom/:id", put(publish_sbom))
        .with_state(state.clone());

    let addr = bind.into();
    tokio::task::spawn(async move {
        loop {
            if state.sync_index().await.is_ok() {
                tracing::info!("Initial index synced");
                break;
            } else {
                tracing::warn!("Index not yet available");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        loop {
            if let Err(e) = state.sync_index().await {
                tracing::info!("Unable to synchronize index: {:?}", e);
            }
            tokio::time::sleep(sync_interval).await;
        }
    });
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}

async fn fetch_sbom(State(state): State<SharedState>, Path(id): Path<String>) -> (StatusCode, Bytes) {
    let storage = state.storage.read().await;
    fetch_object(&storage, &id).await
}

#[derive(Serialize)]
struct FetchResponse {}

async fn fetch_object(storage: &Storage, key: &str) -> (StatusCode, Bytes) {
    match storage.get(&key).await {
        Ok(obj) => {
            tracing::trace!("Retrieved object compressed: {}", obj.compressed);
            if obj.compressed {
                let mut out = Vec::new();
                match ::zstd::stream::copy_decode(&obj.data[..], &mut out) {
                    Ok(_) => (StatusCode::OK, out.into()),
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Bytes::default()),
                }
            } else {
                (StatusCode::OK, obj.data.into())
            }
        }
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            (StatusCode::INTERNAL_SERVER_ERROR, Bytes::default())
        }
    }
}

async fn query_sbom(State(state): State<SharedState>, Query(params): Query<QueryParams>) -> (StatusCode, Bytes) {
    let result = if let Some(purl) = params.purl {
        tracing::trace!("Querying SBOM using purl {}", purl);
        let mut index = state.index.lock().await;
        let result = index.query_purl(&purl).await;
        if let Err(e) = &result {
            tracing::info!("Index entry for pURL {} not found: {:?}", purl, e);
        }
        result
    } else if let Some(sha256) = params.sha256 {
        tracing::trace!("Querying SBOM using sha256 {}", sha256);
        let mut index = state.index.lock().await;
        let result = index.query_sha256(&sha256).await;
        if let Err(e) = &result {
            tracing::info!("Index entry for SHA256 {} not found: {:?}", sha256, e);
        }
        result
    } else {
        return (StatusCode::BAD_REQUEST, Bytes::default());
    };

    match result {
        Ok(key) => {
            let storage = state.storage.read().await;
            fetch_object(&storage, &key).await
        }
        Err(_) => (StatusCode::NOT_FOUND, Bytes::default()),
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    purl: Option<String>,
    sha256: Option<String>,
}

async fn publish_sbom(State(state): State<SharedState>, Path(id): Path<String>, data: Bytes) -> StatusCode {
    let storage = state.storage.write().await;
    // TODO: unbuffered I/O
    tracing::trace!("Storing new SBOM with id {}", id);

    if let Ok(sbom) = SBOM::parse(&data) {
        if let Some(purl) = sbom.purl() {
            let mut out = Vec::new();
            let (data, compressed) = match zstd::stream::copy_encode(sbom.raw(), &mut out, 3) {
                Ok(_) => (&out[..], true),
                Err(_) => (sbom.raw(), false),
            };
            tracing::trace!("Storing new object with compressed: {}", compressed);
            let value = Object::new(&purl, data, compressed);
            match storage.put(&id, value).await {
                Ok(_) => {
                    tracing::trace!("SBOM of size {} stored successfully", &data[..].len());
                    StatusCode::CREATED
                }
                Err(e) => {
                    tracing::warn!("Error storing SBOM: {:?}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        } else {
            // TODO Add description in response
            tracing::trace!("No pURL found");
            StatusCode::BAD_REQUEST
        }
    } else {
        // TODO Add description in response
        tracing::trace!("No valid SBOM uploaded");
        StatusCode::BAD_REQUEST
    }
}
