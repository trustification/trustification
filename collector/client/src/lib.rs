use std::collections::HashMap;
use trustification_auth::client::{TokenInjector, TokenProvider};

use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CollectPackagesRequest {
    pub purls: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CollectVulnerabilitiesRequest {
    pub vulnerability_ids: VulnerabilityIds,
}

pub type VulnerabilityIds = Vec<String>;

#[derive(Serialize, Deserialize, Debug)]
pub struct CollectPackagesResponse {
    #[serde(flatten)]
    pub purls: HashMap<String, VulnerabilityIds>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CollectVulnerabilitiesResponse {
    pub vulnerability_ids: VulnerabilityIds,
}

pub struct CollectorUrl {
    base_url: Url,
}

impl CollectorUrl {
    pub fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    pub fn packages_url(&self) -> Url {
        self.base_url.join("packages").unwrap()
    }

    pub fn vulnerabilities_url(&self) -> Url {
        self.base_url.join("vulnerabilities").unwrap()
    }
}

pub struct CollectorClient {
    url: CollectorUrl,
    provider: Box<dyn TokenProvider>,
}

impl CollectorClient {
    pub fn new<P>(url: Url, provider: P) -> Self
    where
        P: TokenProvider + 'static,
    {
        Self {
            url: CollectorUrl::new(url),
            provider: Box::new(provider),
        }
    }

    pub async fn collect_packages(
        &self,
        request: CollectPackagesRequest,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        let response = reqwest::Client::new()
            .post(self.url.packages_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&request)
            .send()
            .await?;
        let response: CollectPackagesResponse = response.json().await?;
        Ok(response)
    }

    pub async fn collect_vulnerabilities(
        &self,
        request: CollectVulnerabilitiesRequest,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        let response = reqwest::Client::new()
            .post(self.url.vulnerabilities_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&request)
            .send()
            .await?;
        let response: CollectVulnerabilitiesResponse = response.json().await?;
        Ok(response)
    }
}
