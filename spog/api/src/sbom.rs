use std::collections::HashMap;

#[derive(Clone)]
pub struct SbomRegistry {}

// TODO: Implement
impl SbomRegistry {
    pub fn new() -> Self {
        Self {}
    }

    pub fn exists(&self, purl: &str) -> bool {
        false
    }

    pub fn lookup(&self, purl: &str) -> Option<serde_json::Value> {
        None
    }
}
