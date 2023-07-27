use serde::{Deserialize, Serialize};

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

pub struct Gatherer {
    csub_url: String,
}

impl Gatherer {
    pub fn new(csub_url: String) -> Self {
        Self { csub_url }
    }

    pub async fn listen(&self, state: SharedState) {
        let listener = async move {
            loop {
                if let Ok(mut csub) = CollectSubClient::new(self.csub_url.clone()).await {
                    info!("connecting to csub");
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
                                        info!("adding purl {}", purl);
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

    #[allow(unused)]
    pub async fn gather(&self, state: SharedState, request: CollectRequest) {
        let collectors = state.collectors.read().await;
        for response in collectors.gather(state.clone(), request).await {
            for purl in response.purls {
                state.db.insert_purl(purl.as_str()).await.ok();
            }
        }
    }

    pub async fn add_purl(&self, state: SharedState, purl: &str) -> Result<(), anyhow::Error> {
        state.db.insert_purl(purl).await
    }
}
