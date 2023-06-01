use super::{Backend, Error};
use crate::backend::data::Vulnerability;
use crate::backend::Endpoint;
use reqwest::{RequestBuilder, StatusCode};
use spog_model::prelude::*;

pub struct VulnerabilityService {
    backend: Backend,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchOptions {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

impl SearchOptions {
    pub fn apply(&self, mut builder: RequestBuilder) -> RequestBuilder {
        if let Some(limit) = self.limit {
            builder = builder.query(&[("limit", limit)]);
        }

        if let Some(offset) = self.offset {
            builder = builder.query(&[("offset", offset)]);
        }

        builder
    }
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

    pub async fn search(&self, q: &str, options: &SearchOptions) -> Result<SearchResult<Vec<csaf::Csaf>>, Error> {
        let request = self
            .client
            .get(self.backend.join(Endpoint::Search, "/vuln")?)
            .query(&[("q", q)]);

        let request = options.apply(request);

        let response = request.send().await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
