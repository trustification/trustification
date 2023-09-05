use super::*;
use crate::{config::Config, runner::Runner};
use async_trait::async_trait;
use reqwest::Url;
use test_context::AsyncTestContext;

#[async_trait]
impl AsyncTestContext for BombasticContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_bombastic(&config).await
    }
}

impl Urlifier for BombasticContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

pub struct BombasticContext {
    pub url: Url,
    pub provider: ProviderContext,
    pub events: EventBusConfig,
    _runner: Option<Runner>,
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
        };
    }

    #[cfg(not(feature = "with-services"))]
    panic!("Remote trustification server expected");

    #[cfg(feature = "with-services")]
    {
        // No remote server requested, so fire up bombastic on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();
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
                        println!("Bombastic indexer exited with code {code:?}");
                    }
                },
                bapi = bombastic_api().run(Some(listener)) => match bapi {
                    Err(e) => {
                        panic!("Error running bombastic API: {e:?}");
                    }
                    Ok(code) => {
                        println!("Bombastic API exited with code {code:?}");
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
        };

        // ensure it's initialized
        let client = reqwest::Client::new();
        loop {
            let response = client
                .get(context.urlify(format!("/api/v1/sbom?id=none")))
                .inject_token(&context.provider.provider_user)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            if response.status() == StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // return the context
        context
    }
}

pub async fn upload_sbom(context: &BombasticContext, key: &str, input: &serde_json::Value) {
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/sbom?id={key}")))
        .json(input)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

pub async fn delete_sbom(context: &BombasticContext, key: &str) {
    let response = reqwest::Client::new()
        .delete(context.urlify(format!("/api/v1/sbom?id={key}")))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

pub async fn wait_for_search_result<F: Fn(serde_json::Value) -> bool>(
    context: &mut BombasticContext,
    flags: &[(&str, &str)],
    check: F,
) {
    loop {
        let url = context.urlify("/api/v1/sbom/search");
        let response = reqwest::Client::new()
            .get(url)
            .query(flags)
            .inject_token(&context.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: Value = response.json().await.unwrap();
        if check(payload) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// Configuration for the bombastic indexer
#[cfg(feature = "with-services")]
fn bombastic_indexer() -> bombastic_indexer::Run {
    bombastic_indexer::Run {
        stored_topic: "sbom-stored".into(),
        failed_topic: "sbom-failed".into(),
        indexed_topic: "sbom-indexed".into(),
        devmode: true,
        reindex: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            mode: Default::default(),
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

#[cfg(feature = "with-services")]
fn bombastic_api() -> bombastic_api::Run {
    use trustification_storage::Region;
    bombastic_api::Run {
        bind: "127.0.0.1".to_string(),
        port: 8082,
        devmode: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: 32 * 1024 * 1024,
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
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
        auth: testing_auth(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
    }
}
