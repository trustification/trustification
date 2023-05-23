use super::{Backend, Error};
use crate::backend::data::Vulnerability;
use reqwest::StatusCode;

pub struct VulnerabilityService {
    backend: Backend,
    client: reqwest::Client,
}

impl VulnerabilityService {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            client: reqwest::Client::new(),
        }
    }

    pub async fn lookup(&self, cve: &String) -> Result<Option<Vulnerability>, Error> {
        let response = self
            .client
            .get(self.backend.url.join("/api/vulnerability")?)
            .query(&[("cve", cve.to_string())])
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }
}
