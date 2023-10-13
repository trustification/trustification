use crate::{ApplyAccessToken, Backend, Endpoint};
use reqwest::StatusCode;
use spog_model::prelude::SbomReport;
use spog_ui_common::error::*;
use std::rc::Rc;
use url::Url;
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

    pub fn download_href(&self, pkg: impl AsRef<str>) -> Result<Url, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/package/sbom")?;

        url.query_pairs_mut().append_pair("purl", pkg.as_ref()).finish();

        Ok(url)
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<Option<String>, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/package")?;
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
}
