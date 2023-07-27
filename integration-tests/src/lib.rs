use core::future::Future;
use reqwest::StatusCode;
use std::ops::Deref;
use std::sync::Arc;
use std::{net::TcpListener, thread, time::Duration};
use tokio::{select, task::LocalSet, time::timeout};
use trustification_auth::authenticator::config::{AuthenticatorConfig, SingleAuthenticatorClientConfig};
use trustification_auth::client::{TokenInjector, TokenProvider};
use trustification_event_bus::{EventBusConfig, EventBusType};
use trustification_index::IndexConfig;
use trustification_infrastructure::InfrastructureConfig;
use trustification_storage::StorageConfig;

const STORAGE_ENDPOINT: &str = "http://localhost:9000";
const KAFKA_BOOTSTRAP_SERVERS: &str = "localhost:9092";
const SSO_ENDPOINT: &str = "http://localhost:8090/realms/chicken";

/// Static client secret for testing, configured in `deploy/compose/container_files/init-sso/data/client-testing.json`
const SSO_TESTING_CLIENT_SECRET: &str = "R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP";

pub struct TestingContext {
    pub provider: Arc<dyn TokenProvider>,
}

impl Deref for TestingContext {
    type Target = Arc<dyn TokenProvider>;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

pub fn with_bombastic<F, Fut>(context: TestingContext, timeout: Duration, test: F)
where
    F: FnOnce(TestingContext, u16) -> Fut,
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
                        .inject_token(&context.provider).await.unwrap()
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(context, port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

pub fn with_vexination<F, Fut>(context: TestingContext, timeout: Duration, test: F)
where
    F: FnOnce(TestingContext, u16) -> Fut,
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
                        .inject_token(&context.provider).await.unwrap()
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(context, port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

pub fn with_spog<F, Fut>(context: TestingContext, timeout: Duration, test: F)
where
    F: FnOnce(TestingContext, u16) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        with_bombastic(context, timeout, |context, bport| async move {
            thread::spawn(move || {
                with_vexination(context, timeout, |context, vport| async move {
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
                                    .inject_token(&context.provider).await.unwrap()
                                    .send()
                                    .await
                                    .unwrap();
                                if response.status() == StatusCode::OK {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }

                            // Run test
                            test(context, port).await
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
    })
    .join()
    .expect("Thread panicked");
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
        odic: AuthenticatorConfig {
            disabled: false,
            clients: SingleAuthenticatorClientConfig {
                client_ids: vec!["frontend".to_string(), "testing".to_string()],
                issuer_url: SSO_ENDPOINT.to_string(),
                ..Default::default()
            },
        },
    }
}

pub fn with_test_context<'a, F, Fut>(test: F)
where
    F: FnOnce(TestingContext) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let rt = LocalSet::new();
        runtime.block_on(rt.run_until(async move {
            let client = openid::Client::discover(
                "testing".into(),
                Some(SSO_TESTING_CLIENT_SECRET.to_string()),
                None,
                SSO_ENDPOINT.parse().unwrap(),
            )
            .await
            .unwrap();

            let provider = trustification_auth::client::OpenIdTokenProvider::new(client, chrono::Duration::seconds(10));

            // log::info!("Initial access token: {:?}", provider.provide_access_token().await);
            println!("Initial access token: {:?}", provider.provide_access_token().await);

            test(TestingContext {
                provider: Arc::new(provider),
            })
            .await;
        }));
    })
    .join()
    .expect("Thread panicked");
}
