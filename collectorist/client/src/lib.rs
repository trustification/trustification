use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};

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
}

#[derive(Serialize, Deserialize)]
pub struct RegisterResponse {
    pub guac_url: Url,
}

impl CollectoristClient {
    pub fn new(collector_id: String, collectorist_url: Url) -> Self {
        Self {
            collectorist_url: CollectoristUrl::new(collectorist_url, collector_id),
        }
    }

    pub fn register_url(&self) -> Url {
        self.collectorist_url.register_url()
    }

    pub async fn register(&self, config: CollectorConfig) -> Result<RegisterResponse, anyhow::Error> {
        Ok(reqwest::Client::new()
            .post(self.collectorist_url.register_url())
            .json(&config)
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn deregister(&self) -> Result<(), anyhow::Error> {
        reqwest::Client::new()
            .delete(self.collectorist_url.deregister_url())
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
