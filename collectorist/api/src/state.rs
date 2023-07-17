use crate::collector::CollectorConfig;
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct AppState {
    pub(crate) collectors: RwLock<CollectorsState>,
}

#[derive(Default)]
pub struct CollectorsState {
    collectors: HashMap<String, CollectorState>,
}

impl CollectorsState {
    pub fn register(&mut self, id: String, config: CollectorConfig) -> Result<(), ()> {
        self.collectors.insert(id, CollectorState::new(config));
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
}

pub struct CollectorState {
    config: CollectorConfig,
}

impl CollectorState {
    pub fn new(config: CollectorConfig) -> Self {
        Self { config }
    }
}
