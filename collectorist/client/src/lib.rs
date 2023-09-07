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

    pub fn register_collector_url(&self) -> Url {
        self.base_url
            .join(&format!("/api/v1/collector/{}", self.collector_id))
            .unwrap()
    }

    pub fn deregister_collector_url(&self) -> Url {
        self.base_url
            .join(&format!("/api/v1/collector/{}", self.collector_id))
            .unwrap()
    }

    pub fn collect_packages_url(&self) -> Url {
        self.base_url.join("/api/v1/packages").unwrap()
    }

    pub fn collect_vulnerabilities_url(&self) -> Url {
        self.base_url.join("/api/v1/vulnerabilities").unwrap()
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

    pub fn register_collector_url(&self) -> Url {
        self.collectorist_url.register_collector_url()
    }

    pub async fn register_collector(&self, config: CollectorConfig) -> Result<RegisterResponse, anyhow::Error> {
        Ok(reqwest::Client::new()
            .post(self.collectorist_url.register_collector_url())
            .json(&config)
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn deregister_collector(&self) -> Result<(), anyhow::Error> {
        reqwest::Client::new()
            .delete(self.collectorist_url.deregister_collector_url())
            .send()
            .await?;
        Ok(())
    }

    pub async fn collect_packages(&self, purls: Vec<String>) -> Result<(), anyhow::Error> {
        reqwest::Client::new()
            .post(self.collectorist_url.collect_packages_url())
            .json(&CollectPackagesRequest { purls })
            .send()
            .await?;
        Ok(())
    }

    pub async fn collect_vulnerabilities(&self, vuln_ids: Vec<String>) -> Result<(), anyhow::Error> {
        reqwest::Client::new()
            .post(self.collectorist_url.collect_vulnerabilities_url())
            .json(&CollectVulnerabilitiesRequest { vuln_ids })
            .send()
            .await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectPackagesRequest {
    pub purls: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectVulnerabilitiesRequest {
    pub vuln_ids: Vec<String>,
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
