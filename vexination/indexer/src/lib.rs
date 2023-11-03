use std::process::ExitCode;

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::block_in_place;
use trustification_event_bus::EventBusConfig;
use trustification_index::{IndexConfig, IndexStore, WriteIndex};
use trustification_indexer::{actix::configure, Indexer, IndexerStatus, ReindexMode};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};
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

    #[arg(long = "reindex", default_value_t = ReindexMode::OnFailure)]
    pub reindex: ReindexMode,

    #[command(flatten)]
    pub bus: EventBusConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub index: IndexConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let (command_sender, command_receiver) = mpsc::channel(1);
        let status = Arc::new(Mutex::new(IndexerStatus::Running));
        let s = status.clone();
        let c = command_sender.clone();
        let storage = self.storage.clone();
        Infrastructure::from(self.infra)
            .run_with_config(
                "vexination-indexer",
                |_context| async { Ok(()) },
                |context| async move {
                    let index: Box<dyn WriteIndex<Document = csaf::Csaf>> = Box::new(Index::new());
                    let index = block_in_place(|| {
                        IndexStore::new(&self.storage, &self.index, index, context.metrics.registry())
                    })?;
                    let storage =
                        Storage::new(storage.process("vexination", self.devmode), context.metrics.registry())?;
                    let bus = self.bus.create(context.metrics.registry()).await?;
                    if self.devmode {
                        bus.create(&[self.stored_topic.as_str()]).await?;
                    }

                    let mut indexer = Indexer {
                        indexes: vec![index],
                        storage,
                        bus,
                        stored_topic: self.stored_topic.as_str(),
                        indexed_topic: self.indexed_topic.as_str(),
                        failed_topic: self.failed_topic.as_str(),
                        sync_interval: self.index.sync_interval.into(),
                        status: s.clone(),
                        commands: command_receiver,
                        command_sender: c,
                        reindex: self.reindex,
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
