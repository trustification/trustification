use std::process::ExitCode;

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use trustification_event_bus::EventBusConfig;
use trustification_index::{IndexConfig, IndexStore};
use trustification_indexer::{actix::configure, Indexer, IndexerStatus};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::StorageConfig;
use vexination_index::Index;

#[derive(clap::Args, Debug)]
#[command(about = "Run the indexer", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "stored-topic", default_value = "vex-stored")]
    pub stored_topic: String,

    #[arg(long = "indexed-topic", default_value = "vex-indexed")]
    pub indexed_topic: String,

    #[arg(long = "failed-topic", default_value = "vex-failed")]
    pub failed_topic: String,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    /// Reindex all documents at startup
    #[arg(long = "reindex", default_value_t = false)]
    pub reindex: bool,

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
        let (command_sender, command_receiver) = mpsc::channel(1);
        let status = Arc::new(Mutex::new(IndexerStatus::Running));
        let s = status.clone();
        let c = command_sender.clone();
        Infrastructure::from(self.infra)
            .run_with_config(
                "vexination-indexer",
                |metrics| async move {
                    let index = IndexStore::new(&self.index, Index::new(), metrics.registry())?;
                    let storage = self.storage.create("vexination", self.devmode, metrics.registry())?;
                    let interval = self.index.sync_interval.into();
                    let bus = self.bus.create(metrics.registry()).await?;
                    if self.devmode {
                        bus.create(&[self.stored_topic.as_str()]).await?;
                    }

                    if self.reindex {
                        let _ = c.send(trustification_indexer::IndexerCommand::Reindex).await;
                    }

                    let mut indexer = Indexer {
                        index,
                        storage,
                        bus,
                        stored_topic: self.stored_topic.as_str(),
                        indexed_topic: self.indexed_topic.as_str(),
                        failed_topic: self.failed_topic.as_str(),
                        sync_interval: interval,
                        status: s.clone(),
                        commands: command_receiver,
                        command_sender: c,
                    };
                    indexer.run().await
                },
                move |config| {
                    configure(status, command_sender, config);
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
