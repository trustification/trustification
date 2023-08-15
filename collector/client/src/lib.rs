use std::collections::HashMap;

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

pub struct CollectorClient {
    url: String,
}

impl CollectorClient {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    pub async fn collect_packages(
        &self,
        request: CollectPackagesRequest,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        let mut url = self.url.clone();
        url.push_str("/packages");
        let response = reqwest::Client::new().post(url).json(&request).send().await?;
        let response: CollectPackagesResponse = response.json().await?;
        Ok(response)
    }

    pub async fn collect_vulnerabilities(
        &self,
        request: CollectVulnerabilitiesRequest,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        let mut url = self.url.clone();
        url.push_str("/vulnerabilities");
        let response = reqwest::Client::new().post(url).json(&request).send().await?;
        let response: CollectVulnerabilitiesResponse = response.json().await?;
        Ok(response)
    }
}
