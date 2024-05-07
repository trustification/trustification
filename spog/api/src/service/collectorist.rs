use collectorist_client::CollectoristClient;
use std::sync::Arc;
use trustification_auth::client::TokenProvider;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Any(anyhow::Error),
}

pub struct CollectoristService {
    client: CollectoristClient,
}

impl CollectoristService {
    pub fn new(client: reqwest::Client, url: Url, provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            client: CollectoristClient::new(client, "".to_string(), url, provider),
        }
    }

    pub async fn trigger_vulnerability(&self, id: impl Into<String>) -> Result<(), Error> {
        self.client
            .collect_vulnerabilities(vec![id.into()])
            .await
            .map_err(Error::Any)
    }
}
