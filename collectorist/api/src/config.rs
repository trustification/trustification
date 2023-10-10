use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use trustification_infrastructure::endpoint::{self, Endpoint};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct CollectorsConfig {
    pub collectors: HashMap<String, CollectorConfig>,
}

impl CollectorsConfig {
    pub fn devmode() -> Self {
        let mut collectors = HashMap::new();
        collectors.insert(
            "osv".into(),
            CollectorConfig {
                url: endpoint::CollectorOsv::url(),
                interests: vec![Interest::Package, Interest::Vulnerability],
                cadence: default_cadence(),
            },
        );
        collectors.insert(
            "snyk".into(),
            CollectorConfig {
                url: endpoint::CollectorSnyk::url(),
                interests: vec![Interest::Package],
                cadence: default_cadence(),
            },
        );
        collectors.insert(
            "nvd".into(),
            CollectorConfig {
                url: endpoint::CollectorNvd::url(),
                interests: vec![Interest::Vulnerability],
                cadence: default_cadence(),
            },
        );
        Self { collectors }
    }
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
