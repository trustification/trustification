use std::collections::HashMap;

use crate::gatherer::collector::Collector;
use collector_client::GatherResponse;
use collectorist_client::CollectorConfig;
use futures::future::join_all;

use crate::server::collect::CollectRequest;
use crate::SharedState;

#[derive(Default)]
pub struct Collectors {
    collectors: HashMap<String, Collector>,
}

impl Collectors {
    pub async fn register(&mut self, state: SharedState, id: String, config: CollectorConfig) -> Result<(), ()> {
        self.collectors
            .insert(id.clone(), Collector::new(state.clone(), id, config));
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

    pub async fn gather(&self, state: SharedState, request: CollectRequest) -> Vec<GatherResponse> {
        let mut futures = Vec::new();

        for collector in self.collectors.values() {
            futures.push(collector.gather(state.clone(), request.purls.clone()));
        }

        join_all(futures).await.into_iter().flatten().collect()
    }
}
