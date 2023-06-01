#[derive(Clone)]
pub struct SbomRegistry {}

// TODO: Implement
impl SbomRegistry {
    pub fn new() -> Self {
        Self {}
    }

    pub fn exists(&self, _purl: &str) -> bool {
        false
    }

    pub fn lookup(&self, _purl: &str) -> Option<serde_json::Value> {
        None
    }
}
