use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use bombastic_event_bus::Topic;
use bombastic_index::Index;
use bombastic_storage::{Config, Storage};

mod indexer;

#[derive(clap::Args, Debug)]
#[command(about = "Run the indexer", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short = 'i', long = "index")]
    pub(crate) index: PathBuf,

    // TODO: Make optional
    #[arg(long = "kafka-bootstraps-servers", default_value = "localhost:9092")]
    pub(crate) kafka_bootstrap_servers: String,

    #[arg(long = "create-topics", default_value_t = true)]
    pub(crate) create_topics: bool,

    #[arg(long = "stored-topic", default_value = "stored")]
    pub(crate) stored_topic: String,

    #[arg(long = "indexed-topic", default_value = "indexed")]
    pub(crate) indexed_topic: String,

    #[arg(long = "failed-topic", default_value = "failed")]
    pub(crate) failed_topic: String,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) sync_interval_seconds: u64,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index = Index::new(&self.index)?;
        let storage = Storage::new(if self.devmode {
            Config::minio_test()
        } else {
            Config::defaults()?
        })?;
        use bombastic_event_bus::EventBus;
        let kafka = bombastic_event_bus::kafka::KafkaEventBus::new(self.kafka_bootstrap_servers)?;
        if self.create_topics {
            kafka.create(&[Topic::STORED]).await?;
        }
        let interval = Duration::from_secs(self.sync_interval_seconds);
        indexer::run(index, storage, kafka, interval).await?;
        Ok(ExitCode::SUCCESS)
    }
}
