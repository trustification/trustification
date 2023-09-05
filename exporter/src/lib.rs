use std::process::ExitCode;

use guac::collector::emitter::NatsEmitter;
use strum_macros::Display;
use trustification_event_bus::EventBusConfig;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};

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
pub enum DocumentType {
    #[clap(name = "sbom")]
    SBOM,
    #[clap(name = "vex")]
    VEX,
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

    #[arg(long = "stored-topic")]
    pub(crate) stored_topic: Option<String>,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    #[arg(long = "document-type")]
    pub(crate) document_type: DocumentType,

    #[command(flatten)]
    pub(crate) bus: EventBusConfig,

    #[command(flatten)]
    pub(crate) storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("guac-exporter", |metrics| async move {
                let (bucket, topic) = match self.document_type {
                    DocumentType::SBOM => (
                        self.storage.bucket.clone().unwrap_or("bombastic".into()),
                        self.stored_topic.unwrap_or("sbom-stored".into()),
                    ),
                    DocumentType::VEX => (
                        self.storage.bucket.clone().unwrap_or("vexination".into()),
                        self.stored_topic.unwrap_or("vex-stored".into()),
                    ),
                };
                log::info!(
                    "Starting {} exporter using bucket '{}' and topic '{}'",
                    self.document_type,
                    bucket,
                    topic
                );
                let storage = Storage::new(self.storage.process(&bucket, self.devmode), metrics.registry())?;
                let bus = self.bus.create(metrics.registry()).await?;
                let emitter = NatsEmitter::new(&self.guac_url).await?;
                if self.devmode {
                    bus.create(&[topic.as_str()]).await?;
                }
                exporter::run(storage, bus, emitter, topic.as_str()).await
            })
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
