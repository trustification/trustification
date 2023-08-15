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

use guac::collectsub::{CollectSubClient, Entry, Filter};
use log::{info, warn};
use tokio::time::{interval, sleep};

use crate::server::collect::CollectRequest;
use crate::SharedState;

pub struct Coordinator {
    csub_url: String,
}

impl Coordinator {
    pub fn new(csub_url: String) -> Self {
        Self { csub_url }
    }

    pub async fn listen(&self, state: SharedState) {
        let listener = async move {
            loop {
                if let Ok(mut csub) = CollectSubClient::new(self.csub_url.clone()).await {
                    info!("connected to GUAC collect-sub");
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
                    warn!("unable to connect to collect_sub gRPC endpoint, sleeping...");
                    sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
        };

        listener.await
    }

    pub async fn collect_packages(&self, state: SharedState, request: CollectRequest) -> Vec<CollectPackagesResponse> {
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

    pub async fn add_purl(&self, state: SharedState, purl: &str) -> Result<(), anyhow::Error> {
        state.db.insert_purl(purl).await
    }
}
