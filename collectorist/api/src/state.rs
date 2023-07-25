use crate::db::Db;
use tokio::sync::RwLock;

use crate::gatherer::collectors::Collectors;
use crate::gatherer::Gatherer;

pub struct AppState {
    pub(crate) collectors: RwLock<Collectors>,
    pub(crate) gatherer: Gatherer,
    pub(crate) db: Db,
}

impl AppState {
    pub async fn new(csub_url: String) -> Result<Self, anyhow::Error> {
        Ok(Self {
            collectors: Default::default(),
            db: Db::new().await?,
            gatherer: Gatherer::new(csub_url),
        })
    }
}
