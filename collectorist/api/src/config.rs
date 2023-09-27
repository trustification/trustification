use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct CollectorsConfig {
    pub collectors: HashMap<String, CollectorConfig>,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
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
