use collector_client::CollectPackagesResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[allow(clippy::module_inception)]
pub mod collector;
pub mod collectors;

#[derive(Serialize, Deserialize)]
pub enum RateLimit {
    Unlimited,
    PerSecond(u32),
    PerMinute(u32),
    PerHour(u64),
}

use std::time::SystemTime;

use collectorist_client::{CollectPackagesRequest, CollectVulnerabilitiesRequest};
use guac::collectsub::{CollectSubClient, Entry, Filter};
use log::{info, warn};
use reqwest::Url;
use tokio::time::{interval, sleep};
use trustification_infrastructure::health::checks::Probe;

use crate::state::AppState;

pub struct Coordinator {
    csub_url: Url,
}

impl Coordinator {
    pub fn new(csub_url: Url) -> Self {
        Self { csub_url }
    }

    pub async fn listen(&self, state: &AppState, probe: Probe) {
        let listener = async move {
            loop {
                if let Ok(mut csub) = CollectSubClient::new(self.csub_url.to_string()).await {
                    info!("connected to GUAC collect-sub: {}", self.csub_url);
                    probe.set(true);
                    let mut sleep = interval(tokio::time::Duration::from_millis(1000));

                    let mut since_time = SystemTime::now();
                    loop {
                        let nowish = SystemTime::now();
                        let filters = vec![Filter::Purl("*".into())];
                        let results = csub.get(filters, since_time).await;
                        since_time = nowish;
                        if let Ok(results) = results {
                            for entry in &results {
                                match entry {
                                    Entry::Unknown(_) => {}
                                    Entry::Git(_) => {}
                                    Entry::Oci(_) => {}
                                    Entry::Purl(purl) => {
                                        self.add_purl(state.clone(), purl.as_str()).await.ok();
                                    }
                                    Entry::GithubRelease(_) => {}
                                }
                            }
                        }
                        sleep.tick().await;
                    }
                } else {
                    warn!(
                        "unable to connect to collect_sub gRPC endpoint ({}), sleeping...",
                        self.csub_url
                    );
                    sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
        };

        listener.await
    }

    pub async fn collect_packages(
        &self,
        state: &AppState,
        request: CollectPackagesRequest,
    ) -> Vec<CollectPackagesResponse> {
        let collectors = state.collectors.read().await;
        let result = collectors.collect_packages(state.clone(), request).await;

        let vuln_ids: HashSet<_> = result
            .iter()
            .flat_map(|resp| resp.purls.values().flatten())
            .cloned()
            .collect();

        collectors.collect_vulnerabilities(state.clone(), vuln_ids).await;
        result
    }

    pub async fn collect_vulnerabilities(&self, state: &AppState, request: CollectVulnerabilitiesRequest) {
        let collectors = state.collectors.read().await;
        collectors
            .collect_vulnerabilities(state.clone(), request.vuln_ids.iter().cloned().collect::<HashSet<_>>())
            .await;
    }

    pub async fn add_purl(&self, state: &AppState, purl: &str) -> Result<(), anyhow::Error> {
        state.db.insert_purl(purl).await
    }
}
