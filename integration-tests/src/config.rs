use reqwest::Url;
use serde_json::Value;
use trustification_event_bus::{EventBusConfig, EventBusType};

use crate::{create_provider, create_provider_context, ProviderContext};

#[derive(Default)]
pub struct Config {
    pub spog: Option<Url>,
    pub bombastic: Option<Url>,
    pub vexination: Option<Url>,
    issuer: String,
    user: String,
    manager: String,
    secret: String,
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
                    user: std::env::var("TRUST_USER_ID").expect("TRUST_USER_ID is required"),
                    manager: std::env::var("TRUST_MANAGER_ID").expect("TRUST_MANAGER_ID is required"),
                    secret: std::env::var("TRUST_SECRET").expect("TRUST_SECRET is required"),
                }
            }
            _ => Config::default(),
        }
    }

    pub async fn provider(&self) -> ProviderContext {
        match self.spog {
            Some(_) => ProviderContext {
                provider_user: create_provider(&self.user, &self.secret, &self.issuer).await,
                provider_manager: create_provider(&self.manager, &self.secret, &self.issuer).await,
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
