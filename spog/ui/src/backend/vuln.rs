use super::{Backend, Error};
use crate::backend::data::Vulnerability;
use crate::backend::Endpoint;
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
            .get(self.backend.join(Endpoint::Api, "/api/vulnerability")?)
            .query(&[("cve", cve.to_string())])
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }

    pub async fn search(&self, q: &str) -> Result<Vec<csaf::Csaf>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Search, "/vuln")?)
            .query(&[("q", q)])
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
