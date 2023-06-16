use reqwest::{RequestBuilder, StatusCode};
use spog_model::prelude::*;

use super::{Backend, Error};
use crate::backend::Endpoint;

pub struct VexService {
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

impl VexService {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            client: reqwest::Client::new(),
        }
    }

    pub async fn lookup(&self, advisory: &AdvisorySummary) -> Result<Option<csaf::Csaf>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, &advisory.href)?)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }

    /*
    pub async fn search_vulnerabilities(
        &self,
        q: &str,
        options: &SearchOptions,
    ) -> Result<SearchResult<Vec<VulnSummary>>, Error> {
        log::info!("Search query: {}", q);
        let request = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/vulnerability/search")?)
            .query(&[("q", q)]);

        let request = options.apply(request);

        let response = request.send().await?;

        Ok(response.error_for_status()?.json().await?)
    }*/

    pub async fn search_advisories(
        &self,
        q: &str,
        options: &SearchOptions,
    ) -> Result<SearchResult<Vec<AdvisorySummary>>, Error> {
        let request = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/advisory/search")?)
            .query(&[("q", q)]);

        let request = options.apply(request);

        let response = request.send().await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
