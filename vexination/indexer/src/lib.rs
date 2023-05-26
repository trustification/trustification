use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use vexination_index::Index;

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
    pub(crate) index: Option<PathBuf>,

    #[arg(long = "kafka-bootstrap-servers", default_value = "localhost:9092")]
    pub(crate) kafka_bootstrap_servers: String,

    // Event bus used to communicate with other services.
    #[arg(long = "events", value_enum, default_value = "kafka")]
    pub(crate) events: Events,

    #[arg(long = "stored-topic", default_value = "vex-stored")]
    pub(crate) stored_topic: String,

    #[arg(long = "indexed-topic", default_value = "vex-indexed")]
    pub(crate) indexed_topic: String,

    #[arg(long = "failed-topic", default_value = "vex-failed")]
    pub(crate) failed_topic: String,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) sync_interval_seconds: u64,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    #[arg(long = "storage-endpoint", default_value = None)]
    pub(crate) storage_endpoint: Option<String>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index_dir: PathBuf = self.index.unwrap_or_else(|| {
            use rand::RngCore;
            let r = rand::thread_rng().next_u32();
            std::env::temp_dir().join(format!("vexination-index.{}", r))
        });

        std::fs::create_dir(&index_dir)?;

        let index = Index::new(&index_dir)?;

        let storage = trustification_storage::create("vexination", self.devmode, self.storage_endpoint)?;
        use trustification_event_bus::EventBus;
        let interval = Duration::from_secs(self.sync_interval_seconds);
        match self.events {
            Events::Kafka => {
                let bootstrap = &self.kafka_bootstrap_servers;
                let bus = trustification_event_bus::kafka::KafkaEventBus::new(bootstrap.to_string())?;
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
                .await?;
            }
            Events::Sqs => {
                let bus = trustification_event_bus::sqs::SqsEventBus::new().await?;
                indexer::run(
                    index,
                    storage,
                    bus,
                    self.stored_topic.as_str(),
                    self.indexed_topic.as_str(),
                    self.failed_topic.as_str(),
                    interval,
                )
                .await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}
