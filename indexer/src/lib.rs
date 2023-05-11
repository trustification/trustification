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

    #[arg(long = "kafka-bootstraps-servers", default_value = "localhost:9092", group = "kafka")]
    pub(crate) kafka_bootstrap_servers: Option<String>,

    #[arg(long = "create-topics", default_value_t = true, group = "kafka")]
    pub(crate) create_topics: bool,

    #[arg(long = "sqs", group = "sqs", default_value_t = false)]
    pub(crate) sqs: bool,

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
        let interval = Duration::from_secs(self.sync_interval_seconds);
        if let Some(bootstrap) = &self.kafka_bootstrap_servers {
            let bus = bombastic_event_bus::kafka::KafkaEventBus::new(bootstrap.to_string())?;
            if self.create_topics {
                bus.create(&[Topic::STORED]).await?;
            }
            indexer::run(index, storage, bus, interval).await?;
        } else if self.sqs {
            let bus = bombastic_event_bus::sqs::SqsEventBus::new()?;
            indexer::run(index, storage, bus, interval).await?;
        } else {
            return Err(anyhow::anyhow!("One of kafka or sqs must be used"));
        };
        Ok(ExitCode::SUCCESS)
    }
}
