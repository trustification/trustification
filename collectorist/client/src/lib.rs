use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use trustification_auth::client::{TokenInjector, TokenProvider};

#[derive(Clone, Debug)]
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

#[derive(Clone)]
pub struct CollectoristClient {
    collectorist_url: CollectoristUrl,
    client: reqwest::Client,
    provider: Arc<dyn TokenProvider>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterResponse {
    pub guac_url: Url,
}

impl CollectoristClient {
    pub fn new<P>(client: reqwest::Client, collector_id: impl Into<String>, collectorist_url: Url, provider: P) -> Self
    where
        P: TokenProvider + 'static,
    {
        Self {
            client,
            collectorist_url: CollectoristUrl::new(collectorist_url, collector_id.into()),
            provider: Arc::new(provider),
        }
    }

    pub async fn collect_packages(&self, purls: Vec<String>) -> Result<(), anyhow::Error> {
        self.client
            .post(self.collectorist_url.collect_packages_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&CollectPackagesRequest { purls })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn collect_vulnerabilities(&self, vuln_ids: Vec<String>) -> Result<(), anyhow::Error> {
        self.client
            .post(self.collectorist_url.collect_vulnerabilities_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&CollectVulnerabilitiesRequest { vuln_ids })
            .send()
            .await?
            .error_for_status()?;
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
