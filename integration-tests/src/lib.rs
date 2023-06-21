use core::future::Future;
use reqwest::StatusCode;
use std::time::Duration;
use tokio::{select, task::LocalSet, time::timeout};
use trustification_event_bus::{EventBusConfig, EventBusType};
use trustification_index::IndexConfig;
use trustification_infrastructure::InfrastructureConfig;
use trustification_storage::StorageConfig;

#[derive(Clone, Debug)]
pub struct TestContext {
    pub storage_endpoint: String,
    pub kafka_bootstrap_servers: String,
}

/// Run a test with trustification infrastructure. This prepares these services:
///
/// - Bombastic API
/// - Bombastic Indexer
/// - Vexination API
/// - Vexination Indexer
pub fn run_test<F: Future<Output = Result<(), anyhow::Error>>>(timeout: Duration, test: F) {
    let _ = env_logger::try_init();
    let ctx = TestContext {
        storage_endpoint: "http://localhost:9000".into(),
        kafka_bootstrap_servers: "localhost:9092".into(),
    };

    let rt = LocalSet::new();
    let api = ctx.clone();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(rt.run_until(async move {
        select! {
            biased;

            bindexer = bombastic_indexer(&ctx.storage_endpoint, &ctx.kafka_bootstrap_servers).run() => match bindexer {
                Err(e) => {
                    panic!("Error running bombastic indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic indexer exited with code {:?}", code);
                }
            },

            vindexer = vexination_indexer(&ctx.storage_endpoint, &ctx.kafka_bootstrap_servers).run() => match vindexer {
                Err(e) => {
                    panic!("Error running vexination indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination indexer exited with code {:?}", code);
                }
            },


            bapi = bombastic_api(&api.storage_endpoint).run() => match bapi {
                Err(e) => {
                    panic!("Error running bombastic API: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic API exited with code {:?}", code);
                }
            },

            vapi = vexination_api(&api.storage_endpoint).run() => match vapi {
                Err(e) => {
                    panic!("Error running vexination API: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination API exited with code {:?}", code);
                }
            },

            _ = async move {
                let client = reqwest::Client::new();
                // Probe bombastic API
                loop {
                    let response = client
                        .get("http://localhost:8082/api/v1/sbom?id=none")
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Probe vexination API
                loop {
                    let response = client
                        .get("http://localhost:8081/api/v1/vex?advisory=none")
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test.await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }));
}

pub async fn assert_within_timeout<F: Future>(t: Duration, f: F) {
    let result = timeout(t, f).await;
    assert!(
        result.is_ok(),
        "Unable to perform operation successfully within timeout"
    );
}

// Configuration for the bombastic indexer
fn bombastic_indexer(storage_endpoint: &str, kafka_bootstrap_servers: &str) -> bombastic_indexer::Run {
    bombastic_indexer::Run {
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
            endpoint: Some(storage_endpoint.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: kafka_bootstrap_servers.into(),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
        },
    }
}

fn bombastic_api(storage_endpoint: &str) -> bombastic_api::Run {
    bombastic_api::Run {
        bind: "127.0.0.1".to_string(),
        port: 8082,
        devmode: true,
        index: IndexConfig {
            index: None,
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("bombastic".into()),
            endpoint: Some(storage_endpoint.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
        },
    }
}

// Configuration for the vexination indexer
fn vexination_indexer(storage_endpoint: &str, kafka_bootstrap_servers: &str) -> vexination_indexer::Run {
    vexination_indexer::Run {
        stored_topic: "vex-stored".into(),
        failed_topic: "vex-failed".into(),
        indexed_topic: "vex-indexed".into(),
        devmode: true,
        index: IndexConfig {
            index: None,
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("vexination".into()),
            endpoint: Some(storage_endpoint.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: kafka_bootstrap_servers.into(),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
        },
    }
}

fn vexination_api(storage_endpoint: &str) -> vexination_api::Run {
    vexination_api::Run {
        bind: "127.0.0.1".to_string(),
        port: 8081,
        devmode: true,
        index: IndexConfig {
            index: None,
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("vexination".into()),
            endpoint: Some(storage_endpoint.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
        },
    }
}
