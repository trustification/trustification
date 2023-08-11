use guac::client::GuacClient;

#[derive(Clone)]
pub struct GuacService {
    client: GuacClient,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Guac error: {0}")]
    Guac(#[source] anyhow::Error),
}

impl GuacService {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: GuacClient::new(url.into()),
        }
    }

    /// Lookup dependencies for a provided Package URL
    pub async fn get_dependencies(&self, purl: &str) -> Result<(), Error> {
        let packages = self.client.is_dependency(purl).await.map_err(Error::Guac)?;
        // FIXME: we should return some data
        Ok(())
    }
}
