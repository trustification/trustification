use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use std::time::Duration;

use bombastic_index::Index;
use bombastic_storage::{Config, Storage};
use clap::Parser;

mod indexer;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Run(Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Bombastic Indexer",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Run(Run {
                index,
                kafka_bootstrap_servers,
                stored_topic,
                indexed_topic,
                failed_topic,
                sync_interval_seconds,
                create_topics,
            }) => {
                let index = Index::new(&index)?;
                let storage = Storage::new(Config::new_minio_test())?;
                let kafka = bombastic_event_bus::kafka::KafkaEventBus::new(
                    kafka_bootstrap_servers,
                    "indexer".into(),
                    stored_topic,
                    indexed_topic,
                    failed_topic,
                    create_topics,
                )
                .await?;
                let interval = Duration::from_secs(sync_interval_seconds);
                indexer::run(index, storage, kafka, interval).await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

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
}

#[tokio::main]
async fn main() -> impl Termination {
    //env_logger::init();
    tracing_subscriber::fmt::init();
    Cli::parse().run().await
}
