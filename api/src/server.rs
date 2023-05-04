use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bombastic_index::Index;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

// TODO: Figure out a way to not lock since we use it read only
type SharedState = Arc<Mutex<Index>>;

pub async fn run<T: AsRef<Path>, B: Into<SocketAddr>>(
    index: T,
    bind: B,
) -> Result<(), anyhow::Error> {
    let index = Arc::new(Mutex::new(Index::new(index)?));

    let app = Router::new()
        .route("/api/v1/sbom", get(fetch_sbom))
        .route("/api/v1/sbom", post(publish_sbom))
        .with_state(index);

    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn fetch_sbom(
    State(index): State<SharedState>,
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
    State(index): State<SharedState>,
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
