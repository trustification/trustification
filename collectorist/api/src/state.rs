use crate::db::Db;
use reqwest::Url;
use std::path::Path;
use tokio::sync::RwLock;

use crate::coordinator::collectors::Collectors;
use crate::coordinator::Coordinator;

pub struct AppState {
    pub(crate) collectors: RwLock<Collectors>,
    pub(crate) coordinator: Coordinator,
    pub(crate) db: Db,
    pub(crate) guac_url: Url,
}

impl AppState {
    pub async fn new(base: impl AsRef<Path>, csub_url: Url, guac_url: Url) -> Result<Self, anyhow::Error> {
        Ok(Self {
            collectors: Default::default(),
            db: Db::new(base).await?,
            coordinator: Coordinator::new(csub_url),
            guac_url,
        })
    }
}
