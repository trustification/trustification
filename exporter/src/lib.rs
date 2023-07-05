use std::process::ExitCode;

use guac::collector::emitter::NatsEmitter;
use prometheus::Registry;
use strum_macros::Display;
use trustification_event_bus::EventBusConfig;
use trustification_storage::StorageConfig;

pub mod exporter;

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum Events {
    #[clap(name = "kafka")]
    Kafka,
    #[clap(name = "sqs")]
    Sqs,
}

#[derive(clap::ValueEnum, Debug, Clone, Display)]
#[strum(serialize_all = "lowercase")]
pub enum Storage {
    #[clap(name = "bombastic")]
    Bombastic,
    #[clap(name = "vexation")]
    Vexation,
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the exporter", args_conflicts_with_subcommands = true)]
pub struct Run {
    // TODO: change to nats and use infrastructure
    #[arg(long = "guac-url", default_value = "127.0.0.1:4222")]
    pub(crate) guac_url: String,

    // Event bus used to communicate with other services.
    #[arg(long = "events", value_enum, default_value = "kafka")]
    pub(crate) events: Events,

    #[arg(long = "stored-topic", default_value = "sbom-stored")]
    pub(crate) stored_topic: String,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    #[command(flatten)]
    pub(crate) bus: EventBusConfig,

    #[command(flatten)]
    pub(crate) storage: StorageConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        // TODO: Add infrastructure to surface metrics
        let registry = Registry::default();
        let default_bucket = self
            .storage
            .bucket
            .clone()
            .expect("Required parameter --storage-bucket not set");
        let storage = self.storage.create(&default_bucket, self.devmode, &registry)?;
        let bus = self.bus.create(&registry).await?;
        let emitter = NatsEmitter::new(&self.guac_url).await?;
        if self.devmode {
            bus.create(&[self.stored_topic.as_str()]).await?;
        }
        exporter::run(storage, bus, emitter, self.stored_topic.as_str()).await?;
        Ok(ExitCode::SUCCESS)
    }
}
