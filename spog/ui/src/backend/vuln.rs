use csaf::Csaf;
use reqwest::StatusCode;
use spog_model::prelude::*;
use std::rc::Rc;
use trustification_api::Apply;

use super::{Backend, Error};
use crate::backend::{Endpoint, SearchParameters};

pub struct VexService {
    backend: Rc<Backend>,
    client: reqwest::Client,
}

#[derive(PartialEq)]
pub enum Advisory {
    Csaf { csaf: Rc<Csaf>, source: Rc<String> },
    Unknown(Rc<String>),
}

impl Advisory {
    pub fn parse(source: String) -> Self {
        match serde_json::from_str(&source) {
            Ok(csaf) => Advisory::Csaf {
                csaf: Rc::new(csaf),
                source: Rc::new(source),
            },
            Err(_) => Advisory::Unknown(Rc::new(source)),
        }
    }
}

impl VexService {
    pub fn new(backend: Rc<Backend>) -> Self {
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

    pub async fn get(&self, id: impl AsRef<str>) -> Result<Option<String>, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/advisory")?;
        url.query_pairs_mut().append_pair("id", id.as_ref()).finish();

        let response = self.client.get(url).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.text().await?))
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
        options: &SearchParameters,
    ) -> Result<SearchResult<Vec<AdvisorySummary>>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/advisory/search")?)
            .query(&[("q", q)])
            .apply(options)
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
