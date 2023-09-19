use crate::{ApplyAccessToken, Backend, Endpoint};
use spog_model::config::Configuration;
use spog_ui_common::utils::http::CheckStatus;
use std::rc::Rc;
use web_sys::{RequestCache, RequestCredentials};
use yew_oauth2::prelude::*;

pub struct ConfigService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
}

impl ConfigService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self { backend, access_token }
    }

    pub async fn get_config(&self) -> Result<Configuration, String> {
        let url = self
            .backend
            .join(Endpoint::Api, "/api/v1/config")
            .map_err(|err| format!("Unable to build URL: {err}"))?;

        let response = gloo_net::http::Request::get(url.as_str())
            .latest_access_token(&self.access_token)
            .credentials(RequestCredentials::Include)
            .cache(RequestCache::NoStore)
            .send()
            .await
            .map_err(|err| format!("Failed to load config: {err}"))?;

        response
            .check_status()?
            .json()
            .await
            .map_err(|err| format!("Failed to decode config: {err}"))
    }
}
