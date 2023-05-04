use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bombastic_index::Index;
use bombastic_storage::{Config as StorageConfig, Storage};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

// TODO: Figure out a way to not lock since we use it read only
type SharedState = Arc<Mutex<AppState>>;

pub struct AppState {
    index: Index,
    storage: Storage,
}

pub async fn run<T: AsRef<Path>, B: Into<SocketAddr>>(
    index: T,
    bind: B,
) -> Result<(), anyhow::Error> {
    let storage = Storage::new(StorageConfig::new_minio_test())?;
    let index = Index::new(index)?;
    let state = Arc::new(Mutex::new(AppState { storage, index }));

    let app = Router::new()
        .route("/api/v1/sbom", get(fetch_sbom))
        .route("/api/v1/sbom", post(publish_sbom))
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
    Query(params): Query<FetchParams>,
) -> (StatusCode, Json<FetchResponse>) {
    // TODO: Implement
    (StatusCode::NOT_FOUND, Json(FetchResponse {}))
}

#[derive(Debug, Deserialize)]
struct FetchParams {
    purl: Option<String>,
    sha256: Option<String>,
}

#[derive(Serialize)]
struct FetchResponse {}

async fn publish_sbom(
    State(state): State<SharedState>,
    Json(payload): Json<PublishRequest>,
) -> (StatusCode, Json<PublishResponse>) {
    let response = PublishResponse {};
    // TODO: Implement
    (StatusCode::CREATED, Json(response))
}

#[derive(Deserialize)]
struct PublishRequest {
    username: String,
}

#[derive(Serialize)]
struct PublishResponse {}
