use std::{net::SocketAddr, process::ExitCode, str::FromStr, sync::Arc, time::Duration};

use tokio::sync::RwLock;
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};

mod sbom;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        let state = self.configure()?;
        Infrastructure::from(self.infra)
            .run("bombastic-api", || async move {
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

                server::run(state, addr).await
            })
            .await?;
        Ok(ExitCode::SUCCESS)
    }

    fn configure(&mut self) -> anyhow::Result<Arc<AppState>> {
        let index = IndexStore::new(&self.index, bombastic_index::Index::new())?;
        let storage = self.storage.create("bombastic", self.devmode)?;

        let state = Arc::new(AppState {
            storage: RwLock::new(storage),
            index: RwLock::new(index),
        });

        let sync_interval: Duration = self.index.sync_interval.into();
        let sinker = state.clone();
        tokio::task::spawn(async move {
            loop {
                if sinker.sync_index().await.is_ok() {
                    log::info!("Initial bombastic index synced");
                    break;
                } else {
                    log::warn!("Bombastic index not yet available");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            loop {
                if let Err(e) = sinker.sync_index().await {
                    log::info!("Unable to synchronize bombastic index: {:?}", e);
                }
                tokio::time::sleep(sync_interval).await;
            }
        });

        Ok(state)
    }
}

pub(crate) type Index = IndexStore<bombastic_index::Index>;
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
        log::debug!("Bombastic index reloaded");
        Ok(())
    }
}
