mod bom;
mod provider;
mod spog;
mod vex;

pub mod runner;

pub use bom::*;
pub use provider::*;
use serde_json::Value;
pub use spog::*;
pub use vex::*;

use core::future::Future;
use reqwest::StatusCode;
use spog_api::DEFAULT_CRDA_PAYLOAD_LIMIT;
use std::{net::TcpListener, time::Duration};
use tokio::{select, time::timeout};
use trustification_auth::{
    authenticator::config::{AuthenticatorConfig, SingleAuthenticatorClientConfig},
    client::TokenInjector,
    swagger_ui::SwaggerUiOidcConfig,
};
use trustification_event_bus::{EventBusConfig, EventBusType};
use trustification_index::IndexConfig;
use trustification_infrastructure::InfrastructureConfig;
use trustification_storage::StorageConfig;

const STORAGE_ENDPOINT: &str = "http://localhost:9000";
const KAFKA_BOOTSTRAP_SERVERS: &str = "localhost:9092";
const SSO_ENDPOINT: &str = "http://localhost:8090/realms/chicken";

/// Static client secret for testing, configured in `deploy/compose/container_files/init-sso/data/client-*.json`
const SSO_TESTING_CLIENT_SECRET: &str = "R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP";

pub async fn assert_within_timeout<F: Future>(t: Duration, f: F) {
    let result = timeout(t, f).await;
    assert!(
        result.is_ok(),
        "Unable to perform operation successfully within timeout"
    );
}

pub async fn wait_for_event<F: Future>(t: Duration, config: &EventBusConfig, bus_name: &str, id: &str, f: F) {
    let bus = config.create(&prometheus::Registry::new()).await.unwrap();
    let consumer = bus.subscribe("test-client", &[bus_name]).await.unwrap();
    assert_within_timeout(t, async {
        f.await;
        loop {
            if let Ok(Some(event)) = consumer.next().await {
                let payload = event.payload().unwrap();
                if let Ok(v) = serde_json::from_slice::<Value>(payload) {
                    let key = v["key"].as_str().unwrap();
                    if key.ends_with(id) {
                        break;
                    }
                } else {
                    let key = std::str::from_utf8(payload).unwrap();
                    if key.ends_with(id) {
                        break;
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
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

fn spog_api(bport: u16, vport: u16) -> spog_api::Run {
    spog_api::Run {
        devmode: false,
        bind: Default::default(),
        port: 8083,
        guac_url: Default::default(),
        bombastic_url: format!("http://localhost:{bport}").parse().unwrap(),
        vexination_url: format!("http://localhost:{vport}").parse().unwrap(),
        crda_url: option_env!("CRDA_URL").map(|url| url.parse().unwrap()),
        crda_payload_limit: DEFAULT_CRDA_PAYLOAD_LIMIT,
        config: None,
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

fn testing_oidc() -> AuthenticatorConfig {
    AuthenticatorConfig {
        disabled: false,
        clients: SingleAuthenticatorClientConfig {
            client_ids: vec![
                "frontend".to_string(),
                "testing-user".to_string(),
                "testing-manager".to_string(),
            ],
            issuer_url: SSO_ENDPOINT.to_string(),
            ..Default::default()
        },
    }
}

fn testing_swagger_ui_oidc() -> SwaggerUiOidcConfig {
    SwaggerUiOidcConfig {
        swagger_ui_oidc_issuer_url: Some(SSO_ENDPOINT.to_string()),
        swagger_ui_oidc_client_id: "frontend".to_string(),
    }
}

pub async fn get_response(
    port: u16,
    api_endpoint: &str,
    exp_status: reqwest::StatusCode,
    context: &ProviderContext,
) -> Option<Value> {
    let url = format!("http://localhost:{}/{}", port, api_endpoint);
    let response = reqwest::Client::new()
        .get(&url)
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(
        exp_status,
        response.status(),
        "Expected response code does not match with actual response"
    );
    if matches!(exp_status, StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND) {
        None
    } else {
        response.json().await.unwrap()
    }
}

// Return a unique ID
pub fn id(prefix: &str) -> String {
    let uuid = uuid::Uuid::new_v4();
    format!("{prefix}-{uuid}")
}
