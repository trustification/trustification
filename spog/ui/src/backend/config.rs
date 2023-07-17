use super::Backend;
use crate::backend::Endpoint;
use spog_model::config::Configuration;
use std::rc::Rc;
use web_sys::RequestCache;

pub struct ConfigService {
    backend: Rc<Backend>,
}

impl ConfigService {
    pub fn new(backend: Rc<Backend>) -> Self {
        Self { backend }
    }

    pub async fn get_config(&self) -> Result<Configuration, String> {
        let url = self
            .backend
            .join(Endpoint::Api, "/api/v1/config")
            .map_err(|err| format!("Unable to build URL: {err}"))?;

        let response = gloo_net::http::Request::get(url.as_str())
            .cache(RequestCache::NoStore)
            .send()
            .await
            .map_err(|err| format!("Failed to load config: {err}"))?;

        response
            .json()
            .await
            .map_err(|err| format!("Failed to decode config: {err}"))
    }
}
