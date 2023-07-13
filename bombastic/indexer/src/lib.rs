use std::{process::ExitCode, time::Duration};

use trustification_event_bus::{EventBusConfig, EventBusType, KAFKA_BOOTSTRAP_SERVERS};
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{StorageConfig, STORAGE_ENDPOINT};

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

impl Default for Run {
    fn default() -> Self {
        Self {
            stored_topic: "sbom-stored".into(),
            failed_topic: "sbom-failed".into(),
            indexed_topic: "sbom-indexed".into(),
            devmode: true,
            index: IndexConfig {
                index: None,
                sync_interval: Duration::from_secs(2).into(),
            },
            storage: StorageConfig {
                region: None,
                bucket: Some("bombastic".into()),
                endpoint: Some(STORAGE_ENDPOINT.into()),
                access_key: Some("admin".into()),
                secret_key: Some("password".into()),
            },
            bus: EventBusConfig {
                event_bus: EventBusType::Kafka,
                kafka_bootstrap_servers: KAFKA_BOOTSTRAP_SERVERS.into(),
            },
            infra: InfrastructureConfig {
                infrastructure_enabled: false,
                infrastructure_bind: "127.0.0.1".into(),
                infrastructure_workers: 1,
                enable_tracing: false,
            },
        }
    }
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
