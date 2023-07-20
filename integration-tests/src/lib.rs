use core::future::Future;
use reqwest::StatusCode;
use std::{net::TcpListener, thread, time::Duration};
use tokio::{select, task::LocalSet, time::timeout};
use trustification_event_bus::{EventBusConfig, EventBusType};
use trustification_index::IndexConfig;
use trustification_infrastructure::InfrastructureConfig;
use trustification_storage::StorageConfig;

const STORAGE_ENDPOINT: &str = "http://localhost:9000";
const KAFKA_BOOTSTRAP_SERVERS: &str = "localhost:9092";

pub fn with_bombastic<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt = LocalSet::new();
    runtime.block_on(rt.run_until(async move {
        select! {
            biased;

            bindexer = bombastic_indexer().run() => match bindexer {
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

            _ = async move {
                let client = reqwest::Client::new();
                loop {
                    let response = client
                        .get(format!("http://localhost:{port}/api/v1/sbom?id=none"))
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

pub fn with_vexination<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt = LocalSet::new();
    runtime.block_on(rt.run_until(async move {
        select! {
            biased;

            vindexer = vexination_indexer().run() => match vindexer {
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

            _ = async move {
                let client = reqwest::Client::new();
                loop {
                    let response = client
                        .get(format!("http://localhost:{port}/api/v1/vex?advisory=none"))
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

pub fn with_spog<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    with_bombastic(timeout, |bport| async move {
        thread::spawn(move || {
            with_vexination(timeout, |vport| async move {
                select! {
                    biased;

                    spog = spog_api(bport, vport).run(Some(listener)) => match spog {
                        Err(e) => {
                            panic!("Error running spog API: {e:?}");
                        }
                        Ok(code) => {
                            println!("Spog API exited with code {code:?}");
                        }
                    },

                    _ = async move {
                        let client = reqwest::Client::new();
                        loop {
                            let response = client
                                .get(format!("http://localhost:{port}/.well-known/trustification/version"))
                                .send()
                                .await
                                .unwrap();
                            if response.status() == StatusCode::OK {
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }

                        // Run test
                        test(port).await
                    } => {
                        println!("Test completed");
                    }

                    _ = tokio::time::sleep(timeout) => {
                        panic!("Test timed out");
                    }
                }
            })
        })
        .join()
        .expect("Thread panicked");
    })
}

pub async fn assert_within_timeout<F: Future>(t: Duration, f: F) {
    let result = timeout(t, f).await;
    assert!(
        result.is_ok(),
        "Unable to perform operation successfully within timeout"
    );
}

// Configuration for the bombastic indexer
fn bombastic_indexer() -> bombastic_indexer::Run {
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
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
        publish_secret_token: None,
    }
}

// Configuration for the vexination indexer
fn vexination_indexer() -> vexination_indexer::Run {
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
        devmode: true,
        index: IndexConfig {
            index: None,
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
        publish_secret_token: None,
    }
}

fn spog_api(bport: u16, vport: u16) -> spog_api::Run {
    spog_api::Run {
        snyk: Default::default(),
        bind: Default::default(),
        port: 8083,
        guac_url: Default::default(),
        sync_interval_seconds: 10,
        bombastic_url: format!("http://localhost:{bport}").parse().unwrap(),
        vexination_url: format!("http://localhost:{vport}").parse().unwrap(),
        config: None,
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
    }
}
