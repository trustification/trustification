use super::Backend;
use crate::backend::{ApplyAccessToken, Endpoint};
use crate::utils::http::CheckStatus;
use std::rc::Rc;
use trustification_version::VersionInformation;
use web_sys::RequestCache;

#[allow(unused)]
pub struct VersionService {
    backend: Rc<Backend>,
    access_token: Option<String>,
}

#[allow(unused)]
impl VersionService {
    pub fn new(backend: Rc<Backend>, access_token: Option<String>) -> Self {
        Self { backend, access_token }
    }

    pub async fn get_version(&self) -> Result<VersionInformation, String> {
        let url = self
            .backend
            .join(Endpoint::Api, "/.well-known/trustification/version")
            .map_err(|err| format!("Unable to build URL: {err}"))?;

        let response = gloo_net::http::Request::get(url.as_str())
            .cache(RequestCache::NoStore)
            .access_token(&self.access_token)
            .send()
            .await
            .map_err(|err| format!("Failed to load backend information: {err}"))?;

        response
            .check_status()?
            .json()
            .await
            .map_err(|err| format!("Failed to decode backend information: {err}"))
    }
}
