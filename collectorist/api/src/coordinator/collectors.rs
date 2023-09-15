use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::coordinator::collector::Collector;
use collector_client::{CollectPackagesResponse, CollectVulnerabilitiesResponse};
use collectorist_client::{CollectPackagesRequest, CollectorConfig, Interest};
use futures::future::join_all;
use trustification_auth::client::TokenProvider;

use crate::state::AppState;

pub struct Collectors {
    client: reqwest::Client,
    collectors: HashMap<String, Collector>,
    provider: Arc<dyn TokenProvider>,
}

impl Collectors {
    pub fn new<P>(client: reqwest::Client, provider: P) -> Self
    where
        P: TokenProvider + 'static,
    {
        Self {
            client,
            collectors: Default::default(),
            provider: Arc::new(provider),
        }
    }
    pub async fn register(&mut self, state: Arc<AppState>, id: String, config: CollectorConfig) -> Result<(), ()> {
        self.collectors.insert(
            id.clone(),
            Collector::new(self.client.clone(), state, id, config, self.provider.clone()),
        );
        Ok(())
    }

    pub fn deregister(&mut self, id: String) -> Result<bool, ()> {
        Ok(self.collectors.remove(&id).is_some())
    }

    #[allow(unused)]
    pub fn collector_ids(&self) -> impl Iterator<Item = &String> {
        self.collectors.keys()
    }

    pub fn collector_config(&self, id: String) -> Option<CollectorConfig> {
        self.collectors.get(&id).map(|e| e.config.clone())
    }

    pub async fn collect_packages(
        &self,
        state: &AppState,
        request: CollectPackagesRequest,
    ) -> Vec<CollectPackagesResponse> {
        let mut futures = Vec::new();

        for collector in self.collectors.values() {
            log::info!("check pkgs {}", collector.id);
            if collector.config.interests.contains(&Interest::Package) {
                log::info!("dispatch pkgs {}", collector.id);
                futures.push(collector.collect_packages(state.clone(), request.purls.clone()));
            }
        }

        join_all(futures).await.into_iter().flatten().collect()
    }

    pub async fn collect_vulnerabilities(
        &self,
        state: &AppState,
        vuln_ids: HashSet<String>,
    ) -> Vec<CollectVulnerabilitiesResponse> {
        let mut futures = Vec::new();

        for collector in self.collectors.values() {
            log::info!("check vulns {}", collector.id);
            if collector.config.interests.contains(&Interest::Vulnerability) {
                log::info!("dispatch vulns {}", collector.id);
                futures.push(collector.collect_vulnerabilities(state.clone(), vuln_ids.clone()));
            }
        }

        join_all(futures).await.into_iter().flatten().collect()
    }
}
