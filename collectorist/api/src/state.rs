use crate::db::Db;
use reqwest::Url;
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
    pub async fn new(csub_url: Url, guac_url: Url) -> Result<Self, anyhow::Error> {
        Ok(Self {
            collectors: Default::default(),
            db: Db::new().await?,
            coordinator: Coordinator::new(csub_url),
            guac_url,
        })
    }
}
