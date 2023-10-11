use crate::{ApplyAccessToken, Backend, Endpoint, SearchParameters};
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use trustification_api::Apply;
use v11y_model::search::{SearchDocument, SearchHit};
use yew_oauth2::prelude::*;

pub struct CveService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

impl CveService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<cve::Cve, ApiError> {
        let url = self.backend.join(
            Endpoint::Api,
            &format!("/api/v1/cve/{id}", id = urlencoding::encode(id.as_ref())),
        )?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn search(
        &self,
        q: &str,
        options: &SearchParameters,
    ) -> Result<SearchResult<Vec<SearchDocument>>, Error> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/cve")?)
            .query(&[("q", q)])
            .apply(options)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        let result: SearchResult<Vec<SearchHit>> = response.error_for_status()?.json().await?;

        Ok(result.map(|result| result.into_iter().map(|result| result.document).collect()))
    }
}
