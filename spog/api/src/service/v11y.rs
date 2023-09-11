use std::sync::Arc;
use trustification_auth::client::TokenProvider;
use url::Url;
use v11y_client::{V11yClient, Vulnerability};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Any(anyhow::Error),
}

pub struct V11yService {
    client: Option<V11yClient>,
}

impl V11yService {
    pub fn new(url: Option<Url>, provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            client: url.map(|url| V11yClient::new(url, provider)),
        }
    }

    pub async fn fetch(&self, id: &str) -> Result<Vec<Vulnerability>, Error> {
        let client = match &self.client {
            Some(client) => client,
            None => return Ok(vec![]),
        };

        client.get_vulnerability(id).await.map_err(Error::Any)
    }
}
