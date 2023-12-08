use crate::{ApplyAccessToken, Backend, Endpoint};
use spog_model::prelude::Suggestion;
use spog_ui_common::error::{ApiError, ApiErrorForStatus};
use std::rc::Rc;
use web_sys::RequestCache;
use yew_oauth2::context::LatestAccessToken;

#[allow(unused)]
pub struct SuggestionService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
}

#[allow(unused)]
impl SuggestionService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self { backend, access_token }
    }

    pub async fn search(&self, term: &str) -> Result<Vec<Suggestion>, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/suggestions/search")?;
        url.query_pairs_mut().append_pair("term", term);

        let response = gloo_net::http::Request::get(url.as_str())
            .cache(RequestCache::NoStore)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }
}
