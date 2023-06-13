#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::{net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr, sync::Arc, time::Duration};

use tokio::sync::RwLock;
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    #[command(flatten)]
    pub(crate) index: IndexConfig,

    #[command(flatten)]
    pub(crate) storage: StorageConfig,

    #[command(flatten)]
    pub(crate) infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        let state = self.configure()?;
        Infrastructure::from(self.infra)
            .run(|| async {
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

                server::run(state, addr).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    fn configure(&mut self) -> anyhow::Result<Arc<AppState>> {
        let index = IndexStore::new(&self.index, vexination_index::Index::new())?;
        let storage = self.storage.create("vexination", self.devmode)?;

        let state = Arc::new(AppState {
            storage: RwLock::new(storage),
            index: RwLock::new(index),
        });

        let sync_interval = self.index.sync_interval.into();

        let sinker = state.clone();
        tokio::task::spawn(async move {
            loop {
                if sinker.sync_index().await.is_ok() {
                    tracing::info!("Initial vexination index synced");
                    break;
                } else {
                    tracing::warn!("Vexination index not yet available");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            loop {
                if let Err(e) = sinker.sync_index().await {
                    tracing::info!("Unable to synchronize vexination index: {:?}", e);
                }
                tokio::time::sleep(sync_interval).await;
            }
        });

        Ok(state)
    }
}

pub(crate) type Index = IndexStore<vexination_index::Index>;
pub struct AppState {
    storage: RwLock<Storage>,
    index: RwLock<Index>,
}

pub(crate) type SharedState = Arc<AppState>;

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let data = {
            let storage = self.storage.read().await;
            storage.get_index().await?
        };

        let mut index = self.index.write().await;
        index.reload(&data[..])?;
        tracing::debug!("Vexination index reloaded");
        Ok(())
    }
}
