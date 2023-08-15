use std::collections::HashSet;
use std::fmt::Debug;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use collector_client::{
    CollectPackagesRequest, CollectPackagesResponse, CollectVulnerabilitiesRequest, CollectVulnerabilitiesResponse,
    CollectorClient,
};
use collectorist_client::{CollectorConfig, Interest};

use crate::SharedState;

#[derive(Debug, thiserror::Error)]
#[error("No configuration for collector")]
pub struct NoCollectorConfigError;

#[derive(Copy, Clone)]
pub enum RetentionMode {
    All,
    InterestingOnly,
}

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

    pub async fn collect_packages(
        &self,
        state: SharedState,
        purls: Vec<String>,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        Self::collect_packages_internal(
            state,
            self.id.clone(),
            &self.config,
            purls,
            RetentionMode::InterestingOnly,
        )
        .await
    }

    async fn collect_packages_internal(
        state: SharedState,
        id: String,
        config: &CollectorConfig,
        purls: Vec<String>,
        mode: RetentionMode,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        //log::info!("{} scan {:?}", id, purls);
        let client = CollectorClient::new(config.url.clone());

        let response = client
            .collect_packages(CollectPackagesRequest { purls: purls.clone() })
            .await?;

        for purl in response.purls.keys() {
            log::info!("[{}] scanned {} {:?}", id, purl, response.purls.values());
            let _ = state.db.insert_purl(purl).await.ok();
            let _ = state.db.update_purl_scan_time(&id, purl).await.ok();
        }

        if matches!(mode, RetentionMode::All) {
            for purl in &purls {
                let _ = state.db.update_purl_scan_time(&id, purl).await.ok();
            }
        }

        Ok(response)
    }

    pub async fn collect_vulnerabilities(
        &self,
        state: SharedState,
        vulnerability_ids: HashSet<String>,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        Self::collect_vulnerabilities_internal(state, self.id.clone(), &self.config, vulnerability_ids).await
    }

    async fn collect_vulnerabilities_internal(
        state: SharedState,
        id: String,
        config: &CollectorConfig,
        vulnerability_ids: HashSet<String>,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        let client = CollectorClient::new(config.url.clone());

        let response = client
            .collect_vulnerabilities(CollectVulnerabilitiesRequest {
                vulnerability_ids: Vec::from_iter(vulnerability_ids.iter().cloned()),
            })
            .await?;

        for vuln_id in &response.vulnerability_ids {
            log::debug!("[{}] scanned {}", id, vuln_id);
            let _ = state.db.insert_vulnerability(vuln_id).await;
            let _ = state.db.update_vulnerability_scan_time(&id, vuln_id).await;
        }

        Ok(response)
    }

    pub async fn update(state: SharedState, id: String) {
        loop {
            if let Some(config) = state.collectors.read().await.collector_config(id.clone()) {
                let collector_url = config.url.clone();
                if config.interests.contains(&Interest::Package) {
                    let purls: Vec<String> = state
                        .db
                        .get_purls_to_scan(id.as_str(), Utc::now() - chrono::Duration::seconds(1200), 20)
                        .await
                        .collect()
                        .await;

                    if !purls.is_empty() {
                        log::debug!("polling packages for {} -> {}", id, collector_url);
                        if let Ok(response) = Self::collect_packages_internal(
                            state.clone(),
                            id.clone(),
                            &config,
                            purls,
                            RetentionMode::All,
                        )
                        .await
                        {
                            // during normal re-scan, we did indeed discover some vulns, make sure they are in the DB.
                            let vuln_ids: HashSet<_> = response.purls.values().flatten().collect();

                            for vuln_id in vuln_ids {
                                state.db.insert_vulnerability(vuln_id).await.ok();
                            }
                        }
                    }
                }

                if config.interests.contains(&Interest::Vulnerability) {
                    let vuln_ids: HashSet<String> = state
                        .db
                        .get_vulnerabilities_to_scan(id.as_str(), Utc::now() - chrono::Duration::seconds(1200), 20)
                        .await
                        .collect()
                        .await;

                    if !vuln_ids.is_empty() {
                        log::debug!("polling vulnerabilities for {} -> {}", id, collector_url);
                        Self::collect_vulnerabilities_internal(state.clone(), id.clone(), &config, vuln_ids)
                            .await
                            .ok();
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
