use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix_web::middleware::Logger;
use actix_web::web::{self};
use actix_web::{App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use tokio::sync::RwLock;
use trustification_storage::Storage;
use vexination_index::Index;

pub struct AppState {
    pub storage: RwLock<Storage>,
    // TODO: Figure out a way to not lock since we use it read only
    pub index: RwLock<Index>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let data = {
            let storage = self.storage.read().await;
            storage.get_index().await?
        };

        let mut index = self.index.write().await;
        index.reload(&data[..])?;
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
    let index = RwLock::new(index);
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
            .service(web::resource("/").to(search))
            .service(web::resource("/vuln").to(crate::vuln::search))
    })
    .bind(&addr)?
    .run()
    .await?;
    Ok(())
}

pub async fn fetch_object(storage: &Storage, key: &str) -> Option<Vec<u8>> {
    match storage.get(&key).await {
        Ok(obj) => {
            tracing::trace!("Retrieved object compressed: {}", obj.compressed);
            if obj.compressed {
                let mut out = Vec::new();
                match ::zstd::stream::copy_decode(&obj.data[..], &mut out) {
                    Ok(_) => Some(out),
                    Err(_) => None,
                }
            } else {
                Some(obj.data)
            }
        }
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            None
        }
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn search(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> impl Responder {
    let params = params.into_inner();
    tracing::trace!("Querying VEX using {}", params.q);
    let index = state.index.read().await;
    let result = index.search(params.q.as_str(), &[], &[], 0, 10);
    if let Err(e) = &result {
        tracing::info!("Error searching: {:?}", e);
        return HttpResponse::InternalServerError().body(e.to_string());
    }
    let result = result.unwrap();

    let mut ret: Vec<serde_json::Value> = Vec::new();
    let storage = state.storage.read().await;

    for key in result.iter() {
        if let Some(obj) = fetch_object(&storage, &key).await {
            if let Ok(data) = serde_json::from_slice(&obj[..]) {
                ret.push(data);
            }
        }
    }

    HttpResponse::Ok().json(ret)
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub q: String,
}
