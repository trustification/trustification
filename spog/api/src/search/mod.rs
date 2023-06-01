use crate::Run;
use actix_web::web::{self, ServiceConfig};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use trustification_index::IndexStore;
use trustification_storage::Storage;

pub type Index = IndexStore<vexination_index::Index>;

mod vuln;

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub q: String,
}

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

pub async fn fetch_object(storage: &Storage, key: &str) -> Option<Vec<u8>> {
    match storage.get(key).await {
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

pub(crate) fn configure(run: &Run) -> anyhow::Result<impl Fn(&mut ServiceConfig)> {
    let index: PathBuf = run.index.clone().unwrap_or_else(|| {
        use rand::RngCore;
        let r = rand::thread_rng().next_u32();
        std::env::temp_dir().join(format!("search-api.{}", r))
    });

    std::fs::create_dir(&index)?;

    // TODO: Index for bombastic
    let index = IndexStore::new(&index, vexination_index::Index::new())?;
    // TODO: Storage with multiple buckets (bombastic and vexination?)
    let storage = trustification_storage::create("vexination", run.devmode, run.storage_endpoint.clone())?;

    let storage = RwLock::new(storage);
    let index = RwLock::new(index);
    let state = Arc::new(AppState { storage, index });

    let sync_interval = Duration::from_secs(run.sync_interval_seconds);

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

    Ok(move |config: &mut ServiceConfig| {
        config.service(web::resource("/vuln").to(vuln::search));
        config.app_data(web::Data::new(state.clone()));
    })
}
