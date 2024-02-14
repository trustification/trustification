use crate::{ApplyAccessToken, Backend, Endpoint, SearchParameters};
use csaf::Csaf;
use reqwest::{Body, StatusCode};
use spog_model::prelude::*;
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use trustification_api::Apply;
use yew_oauth2::prelude::*;

pub struct VexService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[derive(PartialEq)]
pub enum Advisory {
    Csaf { csaf: Rc<Csaf>, source: Rc<String> },
    Unknown(Rc<String>),
}

impl Advisory {
    pub fn parse(source: String) -> Self {
        match serde_json::from_str(&source) {
            Ok(csaf) => Advisory::Csaf {
                csaf: Rc::new(csaf),
                source: Rc::new(source),
            },
            Err(_) => Advisory::Unknown(Rc::new(source)),
        }
    }

    pub fn get_source(&self) -> Rc<String> {
        match self {
            Self::Csaf { source, .. } => source.clone(),
            Self::Unknown(source) => source.clone(),
        }
    }
}

impl VexService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn lookup(&self, advisory: &AdvisorySummary) -> Result<Option<Csaf>, ApiError> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, &advisory.href)?)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.api_error_for_status().await?.json().await?))
    }

    pub async fn upload(&self, data: impl Into<Body>) -> Result<String, ApiError> {
        let url = self.backend.join(Endpoint::Vexination, "/api/v1/vex")?;

        let response = self
            .client
            .post(url)
            .latest_access_token(&self.access_token)
            .body(data)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.text().await?)
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<Option<String>, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/advisory")?;
        url.query_pairs_mut().append_pair("id", id.as_ref()).finish();

        let response = self
            .client
            .get(url)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(response.api_error_for_status().await?.text().await?))
    }

    pub async fn search_advisories(
        &self,
        q: &str,
        options: &SearchParameters,
    ) -> Result<SearchResult<Vec<AdvisorySummary>>, ApiError> {
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/advisory/search")?)
            .query(&[("q", q)])
            .apply(options)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }
}
