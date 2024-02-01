use std::collections::HashMap;
use std::sync::Arc;

use futures::future::join_all;

use collector_client::{CollectPackagesResponse, CollectorClient};
use collectorist_client::CollectPackagesRequest;
use trustification_auth::client::TokenProvider;

use crate::config::{CollectorConfig, CollectorsConfig, Interest};
use crate::coordinator::collector::Collector;
use crate::state::AppState;

pub struct Collectors {
    collectors: HashMap<String, Collector>,
}

impl Collectors {
    pub fn new<P>(config: &CollectorsConfig, client: reqwest::Client, provider: P) -> Self
    where
        P: TokenProvider + Clone + 'static,
    {
        Self {
            collectors: config
                .collectors
                .iter()
                .map(|(k, v)| {
                    log::info!("collector [{}] at {}", k, v.url);
                    (
                        k.clone(),
                        Collector {
                            id: k.clone(),
                            config: v.clone(),
                            client: Arc::new(CollectorClient::new(client.clone(), v.url.clone(), provider.clone())),
                        },
                    )
                })
                .collect(),
        }
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
                futures.push(collector.collect_packages(state, request.purls.clone()));
            }
        }

        join_all(futures).await.into_iter().flatten().collect()
    }

    pub async fn update(&self, state: Arc<AppState>) {
        let mut update_tasks = Vec::new();

        for (id, collector) in &state.collectors.collectors {
            let handle = tokio::spawn(Collector::update(collector.client.clone(), state.clone(), id.clone()));
            update_tasks.push(handle);
        }

        join_all(update_tasks).await;
    }
}
