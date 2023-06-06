use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::http::header::ContentType;
use actix_web::middleware::Logger;
use actix_web::web::{self, Bytes};
use actix_web::{App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};
use trustification_storage::Storage;
use vexination_model::prelude::*;

type Index = trustification_index::IndexStore<vexination_index::Index>;

struct AppState {
    storage: RwLock<Storage>,
    index: RwLock<Index>,
}

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let data = {
            let storage = self.storage.read().await;
            storage.get_index().await?
        };

        let mut index = self.index.write().await;
        index.reload(&data[..])?;
        info!("Index reloaded");
        Ok(())
    }
}

type SharedState = Arc<AppState>;

pub async fn run<B: Into<SocketAddr>>(
    storage: Storage,
    index: Index,
    bind: B,
    index_sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    let storage = RwLock::new(storage);
    let index = RwLock::new(index);
    let state = Arc::new(AppState { storage, index });

    let sinker = state.clone();
    tokio::task::spawn(async move {
        loop {
            if sinker.sync_index().await.is_ok() {
                info!("Initial index synced");
                break;
            } else {
                warn!("Index not yet available");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        loop {
            if let Err(e) = sinker.sync_index().await {
                info!("Unable to synchronize index: {:?}", e);
            }
            tokio::time::sleep(index_sync_interval).await;
        }
    });

    let addr = bind.into();
    debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .app_data(web::Data::new(state.clone()))
            .service(web::resource("/healthz").to(health))
            .service(
                web::scope("/api/v1")
                    .route("/vex", web::get().to(fetch_vex))
                    .route("/vex/search", web::get().to(search_vex))
                    .route("/vex", web::post().to(publish_vex)),
            )
    })
    .bind(&addr)?
    .run()
    .await?;
    Ok(())
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get_stream(key).await {
        Ok((ctype, stream)) => {
            let ctype = ctype.unwrap_or(ContentType::json().to_string());
            HttpResponse::Ok().content_type(ctype).streaming(stream)
        }
        Err(e) => {
            warn!("Unable to locate object with key {}: {:?}", key, e);
            HttpResponse::NotFound().finish()
        }
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    advisory: Option<String>,
}

async fn fetch_vex(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> HttpResponse {
    let params = params.into_inner();
    let advisory = if let Some(advisory) = params.advisory {
        trace!("Querying VEX using advisory {}", advisory);
        advisory
    } else {
        return HttpResponse::BadRequest().body("Missing valid advisory").into();
    };

    let storage = state.storage.read().await;
    fetch_object(&storage, &advisory).await
}

#[derive(Debug, Deserialize)]
struct PublishParams {
    advisory: Option<String>,
}

async fn publish_vex(state: web::Data<SharedState>, params: web::Query<PublishParams>, data: Bytes) -> HttpResponse {
    let params = params.into_inner();
    let advisory = if let Some(advisory) = params.advisory {
        advisory.to_string()
    } else {
        match serde_json::from_slice::<csaf::Csaf>(&data) {
            Ok(data) => data.document.tracking.id,
            Err(e) => {
                warn!("Unknown input format: {:?}", e);
                return HttpResponse::BadRequest().into();
            }
        }
    };

    let storage = state.storage.write().await;
    debug!("Storing new VEX with id: {advisory}");
    match storage.put_slice(&advisory, ContentType::json().0, &data).await {
        Ok(_) => {
            let msg = format!("VEX of size {} stored successfully", &data[..].len());
            trace!(msg);
            HttpResponse::Created().body(msg)
        }
        Err(e) => {
            let msg = format!("Error storing VEX: {:?}", e);
            warn!(msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

const MAX_LIMIT: usize = 1_000;

async fn search_vex(state: web::Data<SharedState>, params: web::Query<SearchParams>) -> HttpResponse {
    let params = params.into_inner();
    trace!("Querying VEX using {}", params.q);

    let index = state.index.read().await;
    let result = index.search(&params.q, params.offset, params.limit.min(MAX_LIMIT));

    let (result, total) = match result {
        Err(e) => {
            info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok((result, total)) => (result, total),
    };

    let result = SearchResult {
        total: Some(total),
        hits: result
            .iter()
            .map(|r| SearchHit {
                rhsa: r.0.clone(),
                cve: r.1.clone(),
                href: format!("/api/v1/vex?advisory={}", &urlencoding::encode(&r.0)),
            })
            .collect(),
    };
    HttpResponse::Ok().json(result)
}

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
    #[serde(default = "default_offset")]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}
