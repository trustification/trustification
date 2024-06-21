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
use trustification_storage::validator::Validator;

#[async_trait]
impl AsyncTestContext for BombasticContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_bombastic(&config).await
    }

    async fn teardown(self) {
        for fixture in &self.fixtures {
            fixture.cleanup(&self).await;
        }
    }
}

impl HasPushFixture for BombasticContext {
    fn push_fixture(&mut self, fixture: FixtureKind) {
        self.fixtures.push(fixture);
    }
}

#[async_trait]
impl AsyncDeleteById for BombasticContext {
    async fn delete_by_id(&self, id: &str) {
        self.delete_sbom(id).await;
    }
}

impl FileUtility for BombasticContext {}

impl Urlifier for BombasticContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

impl IntoTokenProvider for BombasticContext {
    fn token_provider(&self, kind: ProviderKind) -> &dyn TokenProvider {
        match kind {
            ProviderKind::User => &self.provider.provider_user,
            ProviderKind::Manager => &self.provider.provider_manager,
        }
    }
}

pub struct BombasticContext {
    pub url: Url,
    pub provider: ProviderContext,
    pub events: EventBusConfig,
    _runner: Option<Runner>,
    fixtures: Vec<FixtureKind>,
}

pub async fn start_bombastic(config: &Config) -> BombasticContext {
    // If remote server is configured, use it
    if let Some(url) = config.bombastic.clone() {
        log::debug!("Testing remote bombastic: {url}");
        return BombasticContext {
            url,
            provider: config.provider().await,
            events: config.events(),
            _runner: None,
            fixtures: Vec::new(),
        };
    }

    {
        // No remote server requested, so fire up bombastic on ephemeral port
        let (listener, _, url) = tcp_connection();
        let indexer = bombastic_indexer();
        let events = indexer.bus.clone();

        let runner = Runner::spawn(|| async {
            select! {
                biased;

                bindexer = indexer.run() => match bindexer {
                    Err(e) => {
                        panic!("Error running bombastic indexer: {e:?}");
                    }
                    Ok(code) => {
                        log::info!("Bombastic indexer exited with code {code:?}");
                    }
                },
                bapi = bombastic_api().run(Some(listener)) => match bapi {
                    Err(e) => {
                        panic!("Error running bombastic API: {e:?}");
                    }
                    Ok(code) => {
                        log::info!("Bombastic API exited with code {code:?}");
                    }
                },
            }

            Ok(())
        });

        // Create context right after spawning, as we clean up as soon as the context drops
        let context = BombasticContext {
            url,
            provider: config.provider().await,
            events,
            _runner: Some(runner),
            fixtures: Vec::new(),
        };

        // Ensure it's initialized
        wait_on_service(&context, "sbom", "id").await;

        // Return the context
        context
    }
}

impl BombasticContext {
    pub async fn upload_sbom(&mut self, key: &str, input: &Value) {
        RequestFactory::new()
            .with_provider_manager()
            .post("/api/v1/sbom")
            .with_query(&[("id", key)])
            .with_json(input)
            .expect_status(StatusCode::CREATED)
            .send(self)
            .await;
        self.push_fixture(FixtureKind::Id(String::from(key)));
    }

    pub async fn delete_sbom(&self, key: &str) {
        RequestFactory::<_, Value>::new()
            .with_provider_manager()
            .delete("/api/v1/sbom")
            .with_query(&[("id", key)])
            .expect_status(StatusCode::NO_CONTENT)
            .send(self)
            .await;
    }
}

pub async fn wait_for_package_search_result<T, F>(context: &BombasticContext, flags: &T, check: F) -> Value
where
    T: Serialize + ?Sized,
    F: Fn(&Value) -> bool,
{
    wait_for_search_result(context, flags, check, "/api/v1/package/search").await
}

pub async fn wait_for_sbom_search_result<T, F>(context: &BombasticContext, flags: &T, check: F) -> Value
where
    T: Serialize + ?Sized,
    F: Fn(&Value) -> bool,
{
    wait_for_search_result(context, flags, check, "/api/v1/sbom/search").await
}

async fn wait_for_search_result<T, F>(context: &BombasticContext, flags: &T, check: F, path: &str) -> Value
where
    T: Serialize + ?Sized,
    F: Fn(&Value) -> bool,
{
    let request: RequestFactory<'_, _, Value> = RequestFactory::new()
        .with_provider_manager()
        .get(path)
        .with_query(flags)
        .expect_status(StatusCode::OK);
    loop {
        let payload = request.send(context).await.1.unwrap().try_into().unwrap();
        if check(&payload) {
            return payload;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// Configuration for the bombastic indexer
fn bombastic_indexer() -> bombastic_indexer::Run {
    bombastic_indexer::Run {
        stored_topic: "sbom-stored".into(),
        failed_topic: "sbom-failed".into(),
        indexed_topic: "sbom-indexed".into(),
        devmode: true,
        reindex: Default::default(),
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("bombastic".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validator: Validator::None,
            max_size: ByteSize::gb(1),
        },
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: KAFKA_BOOTSTRAP_SERVERS.into(),
            ..Default::default()
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
    }
}

fn bombastic_api() -> bombastic_api::Run {
    use trustification_storage::Region;
    bombastic_api::Run {
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
            bucket: Some("bombastic".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validator: Validator::SBOM,
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
