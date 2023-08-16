use super::*;
use crate::runner::Runner;
use async_trait::async_trait;
use test_context::AsyncTestContext;

#[async_trait]
impl AsyncTestContext for VexinationContext {
    async fn setup() -> Self {
        let provider = create_provider_context().await;
        start_vexination(provider).await
    }
}

pub struct VexinationContext {
    pub provider: ProviderContext,
    pub port: u16,
    pub config: EventBusConfig,
    _runner: Runner,
}

pub async fn start_vexination(provider: ProviderContext) -> VexinationContext {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let indexer = vexination_indexer();
    let config = indexer.bus.clone();

    let runner = Runner::spawn(|| async {
        select! {
            biased;

            vindexer = indexer.run() => match vindexer {
                Err(e) => {
                    panic!("Error running vexination indexer: {e:?}");
                }
                Ok(code) => {
                    println!("Vexination indexer exited with code {code:?}");
                }
            },

            vapi = vexination_api().run(Some(listener)) => match vapi {
                Err(e) => {
                    panic!("Error running vexination API: {e:?}");
                }
                Ok(code) => {
                    println!("Vexination API exited with code {code:?}");
                }
            },
        }

        Ok(())
    });

    // Create context right after spawning, as we clean up as soon as the context drops

    let context = VexinationContext {
        port,
        provider,
        config,
        _runner: runner,
    };

    // ensure it's initialized

    let client = reqwest::Client::new();
    loop {
        let response = client
            .get(format!("http://localhost:{port}/api/v1/vex?advisory=none"))
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

pub async fn upload_vex(port: u16, input: &serde_json::Value, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/api/v1/vex"))
        .json(input)
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

// Configuration for the vexination indexer
fn vexination_indexer() -> vexination_indexer::Run {
    vexination_indexer::Run {
        stored_topic: "vex-stored".into(),
        failed_topic: "vex-failed".into(),
        indexed_topic: "vex-indexed".into(),
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
            bucket: Some("vexination".into()),
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

fn vexination_api() -> vexination_api::Run {
    vexination_api::Run {
        bind: "127.0.0.1".to_string(),
        port: 8081,
        devmode: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("vexination".into()),
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
