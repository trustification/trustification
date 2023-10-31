use crate::{
    data::{Package, PackageDependencies, PackageList, PackageRef},
    ApplyAccessToken, Backend, Endpoint, SearchParameters,
};
use packageurl::PackageUrl;
use serde::Deserialize;
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

    pub async fn lookup(&self, purl: PackageUrl<'_>) -> Result<Package, Error> {
        Ok(self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/sbom")?)
            .query(&[("purl", purl.to_string())])
            .latest_access_token(&self.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn lookup_batch<'a, I>(&self, purls: I) -> Result<Vec<PackageRef>, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
    {
        self.batch_to_refs("/api/sbom", purls).await
    }

    pub async fn related_packages(&self, purl: impl AsRef<str>) -> Result<PackageDependencies, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!(
                "/api/v1/packages?purl={purl}",
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
                "/api/v1/sbom/dependents?purl={purl}",
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

    /// common call of getting some refs for a batch of purls
    async fn batch_to_refs<'a, I, R>(&self, path: &str, purls: I) -> Result<R, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
        for<'de> R: Deserialize<'de>,
    {
        let purls = PackageList(purls.into_iter().map(|purl| purl.to_string()).collect::<Vec<_>>());

        Ok(self
            .client
            .post(self.backend.join(Endpoint::Api, path)?)
            .json(&purls)
            .latest_access_token(&self.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
