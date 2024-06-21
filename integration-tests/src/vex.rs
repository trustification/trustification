use super::*;
use crate::{
    config::Config,
    provider::{IntoTokenProvider, ProviderKind},
    runner::Runner,
};
use async_trait::async_trait;
use bytesize::ByteSize;
use test_context::AsyncTestContext;
use trustification_auth::client::TokenProvider;
use trustification_indexer::ReindexMode;
use trustification_storage::validator::Validator;

#[async_trait]
impl AsyncTestContext for VexinationContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_vexination(&config).await
    }

    async fn teardown(self) {
        for fixture in &self.fixtures {
            fixture.cleanup(&self).await;
        }
    }
}

impl HasPushFixture for VexinationContext {
    fn push_fixture(&mut self, fixture: FixtureKind) {
        self.fixtures.push(fixture);
    }
}

#[async_trait]
impl AsyncDeleteById for VexinationContext {
    async fn delete_by_id(&self, id: &str) {
        self.delete_vex(id).await;
    }
}

impl FileUtility for VexinationContext {}

impl Urlifier for VexinationContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

impl IntoTokenProvider for VexinationContext {
    fn token_provider(&self, kind: ProviderKind) -> &dyn TokenProvider {
        match kind {
            ProviderKind::User => &self.provider.provider_user,
            ProviderKind::Manager => &self.provider.provider_manager,
        }
    }
}

pub struct VexinationContext {
    pub url: Url,
    pub provider: ProviderContext,
    pub events: EventBusConfig,
    _runner: Option<Runner>,
    fixtures: Vec<FixtureKind>,
}

pub async fn start_vexination(config: &Config) -> VexinationContext {
    // If remote server is configured, use it
    if let Some(url) = config.vexination.clone() {
        log::debug!("Testing remote vexination: {url}");
        return VexinationContext {
            url,
            provider: config.provider().await,
            events: config.events(),
            _runner: None,
            fixtures: Vec::new(),
        };
    }

    {
        // No remote server requested, so fire up vexination on ephemeral port
        let (listener, _, url) = tcp_connection();
        let indexer = vexination_indexer();
        let events = indexer.bus.clone();

        let runner = Runner::spawn(|| async {
            select! {
                biased;

                vindexer = indexer.run() => match vindexer {
                    Err(e) => {
                        panic!("Error running vexination indexer: {e:?}");
                    }
                    Ok(code) => {
                        log::info!("Vexination indexer exited with code {code:?}");
                    }
                },
                vapi = vexination_api().run(Some(listener)) => match vapi {
                    Err(e) => {
                        panic!("Error running vexination API: {e:?}");
                    }
                    Ok(code) => {
                        log::info!("Vexination API exited with code {code:?}");
                    }
                },
            }

            Ok(())
        });

        // Create context right after spawning, as we clean up as soon as the context drops
        let provider = config.provider().await;
        let context = VexinationContext {
            url,
            provider,
            events,
            _runner: Some(runner),
            fixtures: Vec::new(),
        };

        // Ensure it's initialized
        wait_on_service(&context, "vex", "advisory").await;

        // Return the context
        context
    }
}

impl VexinationContext {
    pub async fn upload_vex(&mut self, input: &Value) {
        RequestFactory::<&[(&str, &str)], _>::new()
            .with_provider_manager()
            .post("/api/v1/vex")
            .with_json(input)
            .expect_status(StatusCode::CREATED)
            .send(self)
            .await;
        let id = input["document"]["tracking"]["id"].as_str().unwrap().to_string();
        self.push_fixture(FixtureKind::Id(id));
    }

    pub async fn delete_vex(&self, key: &str) {
        RequestFactory::<_, Value>::new()
            .with_provider_manager()
            .delete("/api/v1/vex")
            .with_query(&[("advisory", key)])
            .expect_status(StatusCode::NO_CONTENT)
            .send(self)
            .await;
    }
}

// Configuration for the vexination indexer
fn vexination_indexer() -> vexination_indexer::Run {
    vexination_indexer::Run {
        stored_topic: "vex-stored".into(),
        indexed_topic: "vex-indexed".into(),
        failed_topic: "vex-failed".into(),
        devmode: true,
        reindex: ReindexMode::Always,
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: KAFKA_BOOTSTRAP_SERVERS.into(),
            ..Default::default()
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("vexination".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validator: Validator::None,
            max_size: ByteSize::gb(1),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
    }
}

fn vexination_api() -> vexination_api::Run {
    use trustification_storage::Region;

    vexination_api::Run {
        devmode: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: Some(Region::Custom {
                endpoint: STORAGE_ENDPOINT.into(),
                region: Region::EuCentral1.to_string(),
            }),
            bucket: Some("vexination".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validator: Validator::VEX,
            max_size: ByteSize::gb(1),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
        auth: testing_auth(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
        http: Default::default(),
        publish_limit: ByteSize::mib(64).into(),
    }
}
