use std::time::Duration;

use serde::{Deserialize, Serialize};

pub struct Client {
    collectorist_url: String,
    collector_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RegisterResponse {
    pub guac_url: String,
}

impl Client {
    pub fn new(collector_id: String, collectorist_url: String) -> Self {
        Self {
            collector_id,
            collectorist_url,
        }
    }

    pub async fn register(&self, config: CollectorConfig) -> Result<RegisterResponse, anyhow::Error> {
        let mut register_url = self.collectorist_url.clone();
        register_url.push_str("api/v1/collector/");
        register_url.push_str(self.collector_id.as_str());

        Ok(reqwest::Client::new()
            .post(&register_url)
            .json(&config)
            .send()
            .await?
            .json()
            .await?)
    }

    pub async fn deregister(&self) -> Result<(), anyhow::Error> {
        let mut deregister_url = self.collectorist_url.clone();
        deregister_url.push_str("api/v1/collector/");
        deregister_url.push_str(self.collector_id.as_str());

        reqwest::Client::new().delete(&deregister_url).send().await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectorConfig {
    pub url: String,
    #[serde(with = "humantime_serde", default = "default_cadence")]
    pub cadence: Duration,
}

pub fn default_cadence() -> Duration {
    Duration::from_secs(30 * 60)
}
