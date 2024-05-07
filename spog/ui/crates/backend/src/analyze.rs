use super::Backend;
use crate::{ApplyAccessToken, Endpoint};
use reqwest::Body;
use spog_ui_common::error::*;
use std::rc::Rc;
use yew_oauth2::prelude::*;

pub struct AnalyzeService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

impl AnalyzeService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    /// send SBOM to CRDA and receive back an HTML report
    pub async fn report(&self, data: impl Into<Body>) -> Result<String, ApiError> {
        let url = self.backend.join(Endpoint::Api, "/api/v1/analyze/report")?;

        let response = self
            .client
            .post(url)
            .latest_access_token(&self.access_token)
            .body(data)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.text().await?)
    }
}
