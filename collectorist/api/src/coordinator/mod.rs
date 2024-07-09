use collector_client::CollectPackagesResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

use collectorist_client::CollectPackagesRequest;
use guac::collectsub::{CollectSubClient, Entry, Filter};
use log::{info, warn};
use reqwest::Url;
use tokio::time::{interval, sleep};
use trustification_infrastructure::health::checks::Probe;

use crate::state::AppState;

pub struct Coordinator {
    csub_url: Url,
    ca_certificate_pem_path: Option<String>,
}

impl Coordinator {
    pub fn new(csub_url: Url, ca_certificate_pem_path: Option<String>) -> Self {
        Self {
            csub_url,
            ca_certificate_pem_path,
        }
    }

    pub async fn update(&self, state: Arc<AppState>) {
        state.collectors.update(state.clone()).await
    }

    pub async fn listen(&self, state: &AppState, probe: Probe) {
        let listener = async move {
            loop {
                let collect_sub_client = match &self.ca_certificate_pem_path {
                    Some(ca_certificate_pem) => {
                        CollectSubClient::new_with_ca_certificate(
                            self.csub_url.to_string(),
                            ca_certificate_pem.to_string(),
                        )
                        .await
                    }
                    None => CollectSubClient::new(self.csub_url.to_string()).await,
                };
                match collect_sub_client {
                    Ok(mut csub) => {
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
                                            self.add_purl(state, purl.as_str()).await.ok();
                                        }
                                        Entry::GithubRelease(_) => {}
                                    }
                                }
                            }
                            sleep.tick().await;
                        }
                    }
                    Err(error) => {
                        warn!(
                            "unable to connect to collect_sub gRPC endpoint ({}) due to {:?}, sleeping...",
                            self.csub_url, error
                        );
                        sleep(tokio::time::Duration::from_secs(10)).await;
                    }
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
        state.collectors.collect_packages(state, request).await
    }

    pub async fn add_purl(&self, state: &AppState, purl: &str) -> Result<(), anyhow::Error> {
        state.db.insert_purl(purl).await
    }
}
