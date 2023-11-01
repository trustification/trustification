use crate::{data::PackageDependencies, ApplyAccessToken, Backend, Endpoint, SearchParameters};
use spog_model::prelude::*;
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use trustification_api::Apply;
use yew_oauth2::prelude::*;

pub struct PackageService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[allow(unused)]
impl PackageService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn related_packages(&self, purl: impl AsRef<str>) -> Result<PackageDependencies, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!(
                "/api/v1/package/related?purl={purl}",
                purl = urlencoding::encode(purl.as_ref())
            ),
        )?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }

    pub async fn dependents(&self, purl: impl AsRef<str>) -> Result<PackageDependencies, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!(
                "/api/v1/package/dependents?purl={purl}",
                purl = urlencoding::encode(purl.as_ref())
            ),
        )?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }

    pub async fn search_packages(
        &self,
        q: &str,
        options: &SearchParameters,
    ) -> Result<SearchResult<Vec<SbomSummary>>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/sbom/search")?)
            .query(&[("q", q)])
            .apply(options)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.error_for_status()?.json().await?)
    }
}
