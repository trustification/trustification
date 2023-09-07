use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use trustification_auth::client::{TokenInjector, TokenProvider};

pub struct CollectoristUrl {
    collector_id: String,
    base_url: Url,
}

impl CollectoristUrl {
    pub fn new(base_url: Url, collector_id: String) -> Self {
        Self { collector_id, base_url }
    }

    pub fn register_url(&self) -> Url {
        self.base_url
            .join(&format!("/api/v1/collector/{}", self.collector_id))
            .unwrap()
    }

    pub fn deregister_url(&self) -> Url {
        self.base_url
            .join(&format!("/api/v1/collector/{}", self.collector_id))
            .unwrap()
    }
}

pub struct CollectoristClient {
    collectorist_url: CollectoristUrl,
    client: reqwest::Client,
    provider: Box<dyn TokenProvider>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterResponse {
    pub guac_url: Url,
}

impl CollectoristClient {
    pub fn new<P>(collector_id: String, collectorist_url: Url, provider: P) -> Self
    where
        P: TokenProvider + 'static,
    {
        Self {
            collectorist_url: CollectoristUrl::new(collectorist_url, collector_id),
            client: reqwest::Client::new(),
            provider: Box::new(provider),
        }
    }

    pub fn register_url(&self) -> Url {
        self.collectorist_url.register_url()
    }

    pub async fn register(&self, config: CollectorConfig) -> Result<RegisterResponse, anyhow::Error> {
        Ok(self
            .client
            .post(self.collectorist_url.register_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&config)
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn deregister(&self) -> Result<(), anyhow::Error> {
        self.client
            .delete(self.collectorist_url.deregister_url())
            .inject_token(self.provider.as_ref())
            .await?
            .send()
            .await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Interest {
    Package,
    Vulnerability,
    Artifact,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectorConfig {
    pub url: Url,
    #[serde(with = "humantime_serde", default = "default_cadence")]
    pub cadence: Duration,

    pub interests: Vec<Interest>,
}

pub fn default_cadence() -> Duration {
    Duration::from_secs(30 * 60)
}
