use crate::{ApplyAccessToken, Backend, Endpoint};
use spog_model::dashboard::{DashboardStatus, Preferences};
use spog_ui_common::error::*;
use std::rc::Rc;
use yew_oauth2::prelude::*;

#[allow(unused)]
pub struct DashboardService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[allow(unused)]
impl DashboardService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_summary(&self) -> Result<DashboardStatus, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/dashboard/status")?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn get_user_preferences(&self) -> Result<Preferences, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/dashboard/userPreferences")?;

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn save_user_preferences(&self, data: Preferences) -> Result<Preferences, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/dashboard/userPreferences")?;

        let response = self
            .client
            .post(url)
            .latest_access_token(&self.access_token)
            .json(&data)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }
}
