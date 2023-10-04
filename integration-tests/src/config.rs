use std::env::VarError;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use reqwest::Url;
use serde_json::Value;
use trustification_event_bus::{EventBusConfig, EventBusType};

use crate::{create_provider, create_provider_context, ProviderContext};

#[derive(Copy, Clone, Debug, Default, strum::EnumString, strum::Display)]
#[strum(serialize_all = "camelCase")]
pub enum DriverKind {
    Firefox,
    #[default]
    Chrome,
}

#[derive(Default, Debug)]
pub struct Config {
    pub spog: Option<Url>,
    pub spog_ui: Option<Url>,
    pub bombastic: Option<Url>,
    pub vexination: Option<Url>,
    issuer: String,
    mgr_id: String,
    mgr_secret: String,
    user_id: Option<String>,
    user_secret: Option<String>,
    pub(crate) ui_dist_path: Option<PathBuf>,
    pub(crate) selenium_driver_url: Option<Url>,
    pub(crate) selenium_driver_kind: DriverKind,
}

impl Config {
    pub async fn new() -> Self {
        let _ = env_logger::try_init();
        match std::env::var("TRUST_URL") {
            Ok(base) => {
                #[allow(clippy::expect_fun_call)]
                let url = Url::parse(&base)
                    .expect(&format!("Invalid TRUST_URL: '{base}'"))
                    .join("/endpoints/backend.json")
                    .unwrap();
                let endpoints: Value = reqwest::get(url.clone())
                    .await
                    .expect("Missing backend endpoints")
                    .json()
                    .await
                    .unwrap();
                Config {
                    spog_ui: Some(url),
                    spog: endpoints["url"].as_str().map(Url::parse).unwrap().ok(),
                    bombastic: endpoints["bombastic"].as_str().map(Url::parse).unwrap().ok(),
                    vexination: endpoints["vexination"].as_str().map(Url::parse).unwrap().ok(),
                    issuer: std::env::var("ISSUER_URL")
                        .unwrap_or(endpoints["oidc"]["issuer"].as_str().unwrap().to_string()),
                    mgr_id: std::env::var("TRUST_ID").expect("TRUST_ID is required"),
                    mgr_secret: std::env::var("TRUST_SECRET").expect("TRUST_SECRET is required"),
                    user_id: std::env::var("TRUST_USER_ID").ok(),
                    user_secret: std::env::var("TRUST_USER_SECRET").ok(),
                    ui_dist_path: std::env::var_os("TRUST_UI_DIST_PATH").map(PathBuf::from),
                    selenium_driver_url: std::env::var("TRUST_SELENIUM_DRIVER_URL")
                        .as_deref()
                        .map(|url| Url::parse(url).unwrap())
                        .ok(),
                    selenium_driver_kind: std::env::var("TRUST_SELENIUM_DRIVER_KIND")
                        .as_deref()
                        .map(|kind| DriverKind::from_str(kind).unwrap())
                        .ok()
                        .unwrap_or_default(),
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
                ..Default::default()
            },
            _ => EventBusConfig::parse(),
        }
    }
}
