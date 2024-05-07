use crate::{ApplyAccessToken, Backend, Endpoint};
use spog_ui_common::error::{ApiError, ApiErrorForStatus};
use std::rc::Rc;
use trustification_version::VersionInformation;
use web_sys::RequestCache;
use yew_oauth2::context::LatestAccessToken;

#[allow(unused)]
pub struct VersionService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
}

#[allow(unused)]
impl VersionService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self { backend, access_token }
    }

    pub async fn get_version(&self) -> Result<VersionInformation, ApiError> {
        let url = self
            .backend
            .join(Endpoint::Api, "/.well-known/trustification/version")?;

        let response = gloo_net::http::Request::get(url.as_str())
            .cache(RequestCache::NoStore)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }
}
