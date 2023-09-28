use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use tokio::time::sleep;

use collector_client::{
    CollectPackagesRequest, CollectPackagesResponse, CollectVulnerabilitiesRequest, CollectVulnerabilitiesResponse,
    CollectorClient,
};

use crate::config::{CollectorConfig, Interest};
use crate::state::AppState;

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
    pub(crate) client: Arc<CollectorClient>,
}

impl Collector {
    pub async fn collect_packages(
        &self,
        state: &AppState,
        purls: Vec<String>,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        Self::collect_packages_internal(
            &self.client,
            state,
            self.id.clone(),
            purls,
            RetentionMode::InterestingOnly,
        )
        .await
    }

    async fn collect_packages_internal(
        client: &CollectorClient,
        state: &AppState,
        id: String,
        purls: Vec<String>,
        mode: RetentionMode,
    ) -> Result<CollectPackagesResponse, anyhow::Error> {
        //log::info!("{} scan {:?}", id, purls);

        let response = client
            .collect_packages(CollectPackagesRequest { purls: purls.clone() })
            .await;

        match response {
            Ok(response) => {
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
            Err(e) => {
                log::warn!("{}", e);
                Err(e)
            }
        }
    }

    pub async fn collect_vulnerabilities(
        &self,
        state: &AppState,
        vulnerability_ids: HashSet<String>,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        Self::collect_vulnerabilities_internal(&self.client, state, self.id.clone(), vulnerability_ids).await
    }

    async fn collect_vulnerabilities_internal(
        client: &CollectorClient,
        state: &AppState,
        id: String,
        vulnerability_ids: HashSet<String>,
    ) -> Result<CollectVulnerabilitiesResponse, anyhow::Error> {
        let response = client
            .collect_vulnerabilities(CollectVulnerabilitiesRequest {
                vulnerability_ids: Vec::from_iter(vulnerability_ids.iter().cloned()),
            })
            .await;

        match response {
            Ok(response) => {
                for vuln_id in &response.vulnerability_ids {
                    log::debug!("[{}] scanned {}", id, vuln_id);
                    let _ = state.db.insert_vulnerability(vuln_id).await;
                    let _ = state.db.update_vulnerability_scan_time(&id, vuln_id).await;
                }
                Ok(response)
            }

            Err(e) => {
                log::warn!("{}", e);
                Err(e)
            }
        }
    }

    pub async fn update(client: Arc<CollectorClient>, state: Arc<AppState>, id: String) {
        loop {
            if let Some(config) = state.collectors.collector_config(id.clone()) {
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
                        if let Ok(response) =
                            Self::collect_packages_internal(&client, &state, id.clone(), purls, RetentionMode::All)
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
                        Self::collect_vulnerabilities_internal(&client, &state, id.clone(), vuln_ids)
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
