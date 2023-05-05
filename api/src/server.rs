use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use bombastic_index::Index;
use bombastic_storage::{Config as StorageConfig, Storage};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

struct AppState {
    storage: RwLock<Storage>,
    // TODO: Figure out a way to not lock since we use it read only
    index: Mutex<Index>,
}

type SharedState = Arc<AppState>;

pub async fn run<T: AsRef<std::path::Path>, B: Into<SocketAddr>>(index: T, bind: B) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(Storage::new(StorageConfig::new_minio_test())?);
    let index = Mutex::new(Index::new(index)?);

    let state = Arc::new(AppState { storage, index });

    let app = Router::new()
        .route("/api/v1/sbom", get(query_sbom))
        .route("/api/v1/sbom/:id", get(fetch_sbom))
        .route("/api/v1/sbom/:id", put(publish_sbom))
        .with_state(state);

    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}

async fn fetch_sbom(State(state): State<SharedState>, Path(id): Path<String>) -> (StatusCode, Bytes) {
    let storage = state.storage.read().await;
    // TODO: Stream payload/SBOM directly from body rather than going via serde_json.
    match storage.get(&id).await {
        Ok(data) => (StatusCode::OK, data.into()),
        Err(e) => (StatusCode::NOT_FOUND, "".into()),
    }
}

#[derive(Serialize)]
struct FetchResponse {}

async fn query_sbom(State(state): State<SharedState>, Query(params): Query<QueryParams>) -> (StatusCode, Bytes) {
    let result = if let Some(purl) = params.purl {
        tracing::info!("Querying SBOM using purl {}", purl);
        let mut index = state.index.lock().await;
        let result = index.query_purl(&purl).await;
        if let Err(e) = &result {
            tracing::info!("Index entry for pURL {} not found: {:?}", purl, e);
        }
        result
    } else if let Some(sha256) = params.sha256 {
        tracing::info!("Querying SBOM using sha256 {}", sha256);
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
            match storage.get(&key).await {
                Ok(data) => (StatusCode::OK, data.into()),
                Err(e) => {
                    tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
                    (StatusCode::INTERNAL_SERVER_ERROR, Bytes::default())
                }
            }
        }
        Err(_) => (StatusCode::NOT_FOUND, Bytes::default()),
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    purl: Option<String>,
    sha256: Option<String>,
}

async fn publish_sbom(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    data: Bytes,
) -> (StatusCode, Json<PublishResponse>) {
    let response = PublishResponse {};
    let storage = state.storage.write().await;
    // TODO: unbuffered I/O
    match storage.put(&id, &data[..]).await {
        Ok(_) => {
            tracing::info!("SBOM of size {} stored successfully", &data[..].len());
            (StatusCode::CREATED, Json(response))
        }
        Err(e) => {
            tracing::warn!("Error storing SBOM: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

#[derive(Serialize)]
struct PublishResponse {}
