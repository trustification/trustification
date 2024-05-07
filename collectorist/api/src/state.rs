use std::path::Path;

use reqwest::Url;

use crate::config::CollectorsConfig;
use trustification_auth::client::TokenProvider;

use crate::coordinator::collectors::Collectors;
use crate::coordinator::Coordinator;
use crate::db::Db;

pub struct AppState {
    pub(crate) collectors: Collectors,
    pub(crate) coordinator: Coordinator,
    pub(crate) db: Db,
}

impl AppState {
    pub async fn new<P>(
        client: reqwest::Client,
        base: impl AsRef<Path>,
        config: &CollectorsConfig,
        csub_url: Url,
        provider: P,
    ) -> Result<Self, anyhow::Error>
    where
        P: TokenProvider + Clone + 'static,
    {
        Ok(Self {
            collectors: Collectors::new(config, client, provider.clone()),
            db: Db::new(base).await?,
            coordinator: Coordinator::new(csub_url),
        })
    }
}
