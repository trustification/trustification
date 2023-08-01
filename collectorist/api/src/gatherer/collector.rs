use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use log::info;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use collector_client::{GatherRequest, GatherResponse};
use collectorist_client::CollectorConfig;

use crate::SharedState;

pub struct Collector {
    pub(crate) id: String,
    pub(crate) config: CollectorConfig,
    pub(crate) update: JoinHandle<()>,
}

impl Collector {
    pub fn new(state: SharedState, id: String, config: CollectorConfig) -> Self {
        let update = tokio::spawn(Collector::update(state.clone(), id.clone()));
        Self {
            id,
            config: config.clone(),
            update,
        }
    }

    pub async fn gather(&self, state: SharedState, purls: Vec<String>) -> Result<GatherResponse, anyhow::Error> {
        let collector_url = self.config.url.clone();

        let response = collector_client::Client::new(collector_url)
            .gather(GatherRequest { purls })
            .await?;

        for purl in &response.purls {
            info!("[{}] scanned {}", self.id, purl);
            let _ = state.db.update_purl_scan_time(&self.id, purl).await;
        }
        Ok(response)
    }

    pub async fn update(state: SharedState, id: String) {
        loop {
            if let Some(config) = state.collectors.read().await.collector_config(id.clone()) {
                let collector_url = config.url;
                let purls: Vec<String> = state
                    .db
                    .get_purls_to_scan(id.as_str(), Utc::now() - chrono::Duration::seconds(1200), 20)
                    .await
                    .collect()
                    .await;

                if !purls.is_empty() {
                    info!("polling for {} -> {}", id, collector_url);
                    if let Ok(_response) = collector_client::Client::new(collector_url)
                        .gather(GatherRequest { purls: purls.clone() })
                        .await
                    {
                        for purl in purls {
                            info!("[{}] scanned {}", id, purl);
                            let _ = state.db.update_purl_scan_time(&id, &purl).await;
                        }
                    }
                }
            }
            // TODO: configurable or smarter for rate-limiting
            sleep(Duration::from_secs(1)).await;
        }
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.update.abort();
    }
}
