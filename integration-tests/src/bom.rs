use super::*;
use crate::runner::Runner;
use async_trait::async_trait;
use test_context::AsyncTestContext;

#[async_trait]
impl AsyncTestContext for BombasticContext {
    async fn setup() -> Self {
        let provider = create_provider_context().await;
        start_bombastic(provider).await
    }
}

pub struct BombasticContext {
    pub provider: ProviderContext,
    pub port: u16,
    pub config: EventBusConfig,
    _runner: Runner,
}

pub async fn start_bombastic(provider: ProviderContext) -> BombasticContext {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let indexer = bombastic_indexer();
    let config = indexer.bus.clone();

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
        port,
        provider,
        config,
        _runner: runner,
    };

    // ensure it's initialized

    let client = reqwest::Client::new();
    loop {
        let response = client
            .get(format!("http://localhost:{port}/api/v1/sbom?id=none"))
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

pub async fn upload_sbom(port: u16, key: &str, input: &serde_json::Value, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .json(input)
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

pub async fn delete_sbom(port: u16, key: &str, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .delete(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .inject_token(&context.provider_manager)
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
    timeout: Duration,
    check: F,
) {
    assert_within_timeout(timeout, async {
        loop {
            let url = format!("http://localhost:{port}/api/v1/sbom/search", port = context.port,);
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
    })
    .await;
}

// Configuration for the bombastic indexer
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

fn bombastic_api() -> bombastic_api::Run {
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
            region: None,
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
        oidc: testing_oidc(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
    }
}
