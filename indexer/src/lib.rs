use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use bombastic_event_bus::Topic;
use bombastic_index::Index;
use bombastic_storage::{Config, Storage};

mod indexer;

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Events {
    #[clap(name = "kafka")]
    Kafka,
    #[clap(name = "sqs")]
    Sqs,
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the indexer", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short = 'i', long = "index")]
    pub(crate) index: PathBuf,

    #[arg(long = "kafka-bootstraps-servers", default_value = "localhost:9092")]
    pub(crate) kafka_bootstrap_servers: String,

    // Event bus used to communicate with other services.
    #[arg(long = "events", value_enum)]
    pub(crate) events: Events,

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
        let storage = if self.devmode {
            Storage::new(Config::test(), bombastic_storage::StorageType::Minio)?
        } else {
            Storage::new(Config::defaults()?, bombastic_storage::StorageType::S3)?
        };
        use bombastic_event_bus::EventBus;
        let interval = Duration::from_secs(self.sync_interval_seconds);
        match self.events {
            Events::Kafka => {
                let bootstrap = &self.kafka_bootstrap_servers;
                let bus = bombastic_event_bus::kafka::KafkaEventBus::new(bootstrap.to_string())?;
                if self.devmode {
                    bus.create(&[Topic::STORED]).await?;
                }
                indexer::run(index, storage, bus, interval).await?;
            }
            Events::Sqs => {
                let bus = bombastic_event_bus::sqs::SqsEventBus::new().await?;
                indexer::run(index, storage, bus, interval).await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}
