use std::env::VarError;

use reqwest::Url;
use serde_json::Value;
use trustification_event_bus::{EventBusConfig, EventBusType};

use crate::{create_provider, create_provider_context, ProviderContext};

#[derive(Default, Debug)]
pub struct Config {
    pub spog: Option<Url>,
    pub bombastic: Option<Url>,
    pub vexination: Option<Url>,
    pub bombastic_failed_topic: String,
    pub vexination_failed_topic: String,
    issuer: String,
    mgr_id: String,
    mgr_secret: String,
    user_id: Option<String>,
    user_secret: Option<String>,
}

impl Config {
    pub async fn new() -> Self {
        let _ = env_logger::try_init();
        match std::env::var("TRUST_URL") {
            Ok(base) => {
                let url = Url::parse(&base)
                    .expect(&format!("Invalid TRUST_URL: '{base}'"))
                    .join("/endpoints/backend.json")
                    .unwrap();
                let endpoints: Value = reqwest::get(url)
                    .await
                    .expect("Missing backend endpoints")
                    .json()
                    .await
                    .unwrap();
                Config {
                    spog: endpoints["url"].as_str().map(Url::parse).unwrap().ok(),
                    bombastic: endpoints["bombastic"].as_str().map(Url::parse).unwrap().ok(),
                    vexination: endpoints["vexination"].as_str().map(Url::parse).unwrap().ok(),
                    issuer: endpoints["oidc"]["issuer"].as_str().unwrap().to_string(),
                    mgr_id: std::env::var("TRUST_ID").expect("TRUST_ID is required"),
                    mgr_secret: std::env::var("TRUST_SECRET").expect("TRUST_SECRET is required"),
                    user_id: std::env::var("TRUST_USER_ID").ok(),
                    user_secret: std::env::var("TRUST_USER_SECRET").ok(),
                    bombastic_failed_topic: std::env::var("TRUST_BOMBASTIC_FAILED_TOPIC")
                        .unwrap_or("sbom-failed".to_string()),
                    vexination_failed_topic: std::env::var("TRUST_VEXINATION_FAILED_TOPIC")
                        .unwrap_or("vex-failed".to_string()),
                }
            }
            Err(VarError::NotPresent) => Config::default(),
            Err(e) => panic!("Unexpected error reading environment variable: {e}"),
        }
    }

    pub async fn provider(&self) -> ProviderContext {
        // For convenience, we default the user's id/secret to that of
        // the manager, but this will break any tests that require a
        // user's role to be less authorized than a manager.
        let user_id = self.user_id.as_ref().unwrap_or(&self.mgr_id);
        let user_secret = self.user_secret.as_ref().unwrap_or(&self.mgr_secret);

        match self.spog {
            Some(_) => ProviderContext {
                provider_user: create_provider(user_id, user_secret, &self.issuer).await,
                provider_manager: create_provider(&self.mgr_id, &self.mgr_secret, &self.issuer).await,
            },
            _ => create_provider_context().await,
        }
    }

    pub fn events(&self) -> EventBusConfig {
        match std::env::var("KAFKA_BOOTSTRAP_SERVERS") {
            Ok(v) => EventBusConfig {
                event_bus: EventBusType::Kafka,
                kafka_bootstrap_servers: v,
            },
            _ => EventBusConfig {
                event_bus: EventBusType::Sqs,
                kafka_bootstrap_servers: String::new(),
            },
        }
    }
}
