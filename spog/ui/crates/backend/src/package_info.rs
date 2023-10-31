use crate::{ApplyAccessToken, Backend, Endpoint, SearchParameters};
use spog_model::prelude::*;
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use trustification_api::Apply;
use yew_oauth2::prelude::*;

pub struct PackageInfoService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[allow(unused)]
impl PackageInfoService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<PackageInfoSummary, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!("/api/v1/package/{id}", id = urlencoding::encode(id.as_ref())),
        )?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn get_related_products(&self, id: impl AsRef<str>) -> Result<PackageProductDetails, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!(
                "/api/v1/package/{id}/related-products",
                id = urlencoding::encode(id.as_ref())
            ),
        )?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn search_packages(
        &self,
        q: &str,
        options: &SearchParameters,
    ) -> Result<SearchResult<Vec<PackageInfoSummary>>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/package/search")?)
            .query(&[("q", q)])
            .apply(options)
            .latest_access_token(&self.access_token)
            .send()
            .await?;
        log::warn!("pub async fn search_packages");
        Ok(response.error_for_status()?.json().await?)
    }
}
