use std::path::Path;

use reqwest::Url;
use tokio::sync::RwLock;

use trustification_auth::client::TokenProvider;

use crate::coordinator::collectors::Collectors;
use crate::coordinator::Coordinator;
use crate::db::Db;

pub struct AppState {
    pub(crate) collectors: RwLock<Collectors>,
    pub(crate) coordinator: Coordinator,
    pub(crate) db: Db,
    pub(crate) guac_url: Url,
}

impl AppState {
    pub async fn new<P>(
        client: reqwest::Client,
        base: impl AsRef<Path>,
        csub_url: Url,
        guac_url: Url,
        provider: P,
    ) -> Result<Self, anyhow::Error>
    where
        P: TokenProvider + Clone + 'static,
    {
        Ok(Self {
            collectors: RwLock::new(Collectors::new(client, provider.clone())),
            db: Db::new(base).await?,
            coordinator: Coordinator::new(csub_url),
            guac_url,
        })
    }
}
