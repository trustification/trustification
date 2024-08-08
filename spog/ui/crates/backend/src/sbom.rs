use crate::{ApplyAccessToken, Backend, Endpoint};
use reqwest::{Body, StatusCode};
use serde::{Deserialize, Serialize};
use spog_model::prelude::{SbomReport, SbomSummary};
use spog_ui_common::error::*;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use uuid::Uuid;
use yew_oauth2::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Vulnerabilities {
    none: usize,
    low: usize,
    medium: usize,
    high: usize,
    critical: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomVulnerabilitySummary {
    sbom_id: String,
    sbom_name: String,
    vulnerabilities: Vulnerabilities,
}

#[allow(unused)]
pub struct SBOMService {
    backend: Rc<Backend>,
    access_token: Option<LatestAccessToken>,
    client: reqwest::Client,
}

#[allow(unused)]
impl SBOMService {
    pub fn new(backend: Rc<Backend>, access_token: Option<LatestAccessToken>) -> Self {
        Self {
            backend,
            access_token,
            client: reqwest::Client::new(),
        }
    }

    pub async fn upload(&self, data: impl Into<Body>) -> Result<String, ApiError> {
        let id = Uuid::new_v4().to_string();

        let url = self
            .backend
            .join(Endpoint::Bombastic, &format!("/api/v1/sbom?id={id}"))?;

        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .latest_access_token(&self.access_token)
            .body(data)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.text().await?)
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<Option<String>, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/sbom")?;
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

    pub async fn get_from_index(&self, id: &str) -> Result<SearchResult<Vec<SbomSummary>>, ApiError> {
        let q = format!("id:{id}");
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/sbom/search")?)
            .query(&[("q", q)])
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn get_sbom_vulns(&self, id: impl AsRef<str>) -> Result<Option<SbomReport>, ApiError> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/sbom/vulnerabilities")?;
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

        Ok(Some(response.api_error_for_status().await?.json().await?))
    }

    pub async fn get_package(&self, id: &str) -> Result<SearchResult<Vec<SbomSummary>>, ApiError> {
        let q = format!(r#"uid:"{id}""#);
        let response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/sbom/search")?)
            .query(&[("q", q)])
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }

    pub async fn get_latest_with_vulns(&self) -> Result<Vec<SbomVulnerabilitySummary>, ApiError> {
        let response: reqwest::Response = self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/v1/sbom/latestwithvulns")?)
            .latest_access_token(&self.access_token)
            .send()
            .await?;

        Ok(response.api_error_for_status().await?.json().await?)
    }
}
