use crate::{ApplyAccessToken, Backend, Endpoint};
use reqwest::StatusCode;
use spog_model::prelude::{SbomReport, SbomSummary};
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use yew_oauth2::prelude::*;

#[allow(unused)]
pub struct SBOMService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[allow(unused)]
impl SBOMService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<Option<String>, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/sbom")?;
        url.query_pairs_mut().append_pair("id", id.as_ref()).finish();

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.text().await?))
    }

    pub async fn get_sbom_vulns(&self, id: impl AsRef<str>) -> Result<Option<SbomReport>, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/sbom/vulnerabilities")?;
        url.query_pairs_mut().append_pair("id", id.as_ref()).finish();

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.error_for_status()?.json().await?))
    }

    pub async fn get_package(&self, id: &str) -> Result<SearchResult<Vec<SbomSummary>>, Error> {
        let q = format!("id:{id}");
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/sbom/search")?)
            .query(&[("q", q)])
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
