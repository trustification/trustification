use super::Backend;
use crate::backend::Endpoint;
use std::rc::Rc;
use trustification_version::VersionInformation;
use web_sys::RequestCache;

pub struct ConfigService {
    backend: Rc<Backend>,
}

impl ConfigService {
    pub fn new() -> Self {
        Self { backend }
    }

    pub async fn get_search_config(&self) -> Result<VersionInformation, String> {
        let url = self
            .backend
            .join(Endpoint::Api, "/.well-known/trustification/version")
            .map_err(|err| format!("Unable to build URL: {err}"))?;

        let response = gloo_net::http::Request::get(url.as_str())
            .cache(RequestCache::NoStore)
            .send()
            .await
            .map_err(|err| format!("Failed to load backend information: {err}"))?;

        response
            .json()
            .await
            .map_err(|err| format!("Failed to decode backend information: {err}"))
    }
}
