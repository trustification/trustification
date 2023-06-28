use std::process::ExitCode;

use trustification_event_bus::EventBusConfig;
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::StorageConfig;

mod indexer;

#[derive(clap::Args, Debug)]
#[command(about = "Run the indexer", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "stored-topic", default_value = "sbom-stored")]
    pub stored_topic: String,

    #[arg(long = "indexed-topic", default_value = "sbom-indexed")]
    pub indexed_topic: String,

    #[arg(long = "failed-topic", default_value = "sbom-failed")]
    pub failed_topic: String,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub bus: EventBusConfig,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("bombastic-indexer", |metrics| async move {
                let index = IndexStore::new(&self.index, bombastic_index::Index::new(), metrics.registry())?;
                let storage = self.storage.create("bombastic", self.devmode, metrics.registry())?;

                let interval = self.index.sync_interval.into();
                let bus = self.bus.create(metrics.registry()).await?;
                if self.devmode {
                    bus.create(&[self.stored_topic.as_str()]).await?;
                }
                indexer::run(
                    index,
                    storage,
                    bus,
                    self.stored_topic.as_str(),
                    self.indexed_topic.as_str(),
                    self.failed_topic.as_str(),
                    interval,
                )
                .await
            })
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
