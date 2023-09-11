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
    client: Option<CollectoristClient>,
}

impl CollectoristService {
    pub fn new(url: Option<Url>, provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            client: url.map(|url| CollectoristClient::new("".to_string(), url, provider)),
        }
    }

    pub async fn trigger_vulnerability(&self, id: impl Into<String>) -> Result<(), Error> {
        let client = match &self.client {
            Some(client) => client,
            None => return Ok(()),
        };

        client
            .collect_vulnerabilities(vec![id.into()])
            .await
            .map_err(Error::Any)
    }
}
