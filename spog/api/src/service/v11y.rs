use crate::search::QueryParams;
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::SearchResult;
use trustification_auth::client::TokenProvider;
use url::Url;
use v11y_client::{V11yClient, Vulnerability};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Any(anyhow::Error),
}

pub struct V11yService {
    client: V11yClient,
}

impl V11yService {
    pub fn new(client: reqwest::Client, url: Url, provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            client: V11yClient::new(client, url, provider),
        }
    }

    #[allow(unused)]
    pub async fn fetch(&self, id: &str) -> Result<Vec<Vulnerability>, Error> {
        self.client.get_vulnerability(id).await.map_err(Error::Any)
    }

    pub async fn fetch_by_alias(&self, alias: &str) -> Result<Vec<Vulnerability>, Error> {
        self.client.get_vulnerability(alias).await.map_err(Error::Any)
    }

    #[instrument(skip(self), ret, err)]
    pub async fn search(&self, query: QueryParams) -> Result<SearchResult<Vec<Vulnerability>>, Error> {
        self.client
            .search(&query.q, query.offset, query.limit)
            .await
            .map_err(Error::Any)
    }
}
