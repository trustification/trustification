use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
    Json, Router,
};
use bombastic_index::Index;
use bombastic_storage::{Config as StorageConfig, Storage};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

struct AppState {
    storage: RwLock<Storage>,
    // TODO: Figure out a way to not lock since we use it read only
    index: Mutex<Index>,
}

type SharedState = Arc<AppState>;

pub async fn run<T: AsRef<std::path::Path>, B: Into<SocketAddr>>(
    index: T,
    bind: B,
) -> Result<(), anyhow::Error> {
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
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn fetch_sbom(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> (StatusCode, Bytes) {
    let storage = state.storage.read().await;
    // TODO: Stream payload/SBOM directly from body rather than going via serde_json.
    match storage.get(&id).await {
        Ok(data) => (StatusCode::NOT_FOUND, data.into()),
        Err(e) => (StatusCode::NOT_FOUND, "".into()),
    }
}

#[derive(Serialize)]
struct FetchResponse {}

async fn query_sbom(
    State(state): State<SharedState>,
    Query(params): Query<QueryParams>,
) -> (StatusCode, Json<QueryResponse>) {
    // TODO: Implement
    (StatusCode::NOT_FOUND, Json(QueryResponse {}))
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    purl: Option<String>,
    sha256: Option<String>,
}

#[derive(Serialize)]
struct QueryResponse {}

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
