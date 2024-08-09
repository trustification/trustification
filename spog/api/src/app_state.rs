use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use tracing::instrument;

use trustification_api::search::SearchOptions;
use trustification_api::Apply;
use trustification_auth::client::{TokenInjector, TokenProvider};
use trustification_infrastructure::tracing::PropagateCurrentContext;

use crate::error::Error;

pub struct AppState {
    pub client: reqwest::Client,
    pub provider: Arc<dyn TokenProvider>,
    pub bombastic: reqwest::Url,
    pub vexination: reqwest::Url,
    pub exhort: reqwest::Url,
}

impl AppState {
    #[instrument(skip(self, provider), err)]
    pub async fn get_sbom(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        let response = self
            .client
            .get(url)
            .query(&[("id", id)])
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.bytes_stream())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn post_sbom(&self, id: &str, provider: &dyn TokenProvider, data: Bytes) -> Result<(), Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        self.client
            .put(url)
            .body(data)
            .query(&[("id", id)])
            .header("content-type", "application/json")
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn search_sbom(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<bombastic_model::search::SearchResult, Error> {
        let url = self.bombastic.join("/api/v1/sbom/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<bombastic_model::prelude::SearchResult>().await?)
    }

    #[instrument(skip(self, provider), err)]
    pub async fn search_package(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<bombastic_model::packages::SearchPackageResult, Error> {
        let url = self.bombastic.join("/api/v1/package/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<bombastic_model::prelude::SearchPackageResult>().await?)
    }

    #[instrument(skip(self, provider), err)]
    pub async fn get_vex(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        let response = self
            .client
            .get(url)
            .query(&[("advisory", id)])
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.bytes_stream())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn post_vex(&self, id: &str, provider: &dyn TokenProvider, data: Bytes) -> Result<(), Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        self.client
            .put(url)
            .body(data)
            .query(&[("id", id)])
            .header("content-type", "application/json")
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn get_vex_status(
        &self,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<vexination_model::search::StatusResult, Error> {
        let url = self.vexination.join("/api/v1/vex/status")?;
        let response = self
            .client
            .get(url)
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<vexination_model::prelude::StatusResult>().await?)
    }

    #[instrument(skip(self, provider), err)]
    pub async fn get_sbom_status(
        &self,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<bombastic_model::search::StatusResult, Error> {
        let url = self.bombastic.join("/api/v1/sbom/status")?;
        let response = self
            .client
            .get(url)
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<bombastic_model::prelude::StatusResult>().await?)
    }

    #[instrument(skip(self, provider), err)]
    pub async fn search_vex(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<vexination_model::search::SearchResult, Error> {
        let url = self.vexination.join("/api/v1/vex/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<vexination_model::prelude::SearchResult>().await?)
    }
}

#[async_trait]
pub trait ResponseError: Sized {
    async fn or_status_error(self) -> Result<Self, Error>;

    async fn or_status_error_opt(self) -> Result<Option<Self>, Error>;
}

#[async_trait]
impl ResponseError for reqwest::Response {
    async fn or_status_error(self) -> Result<Self, Error> {
        if self.status().is_success() {
            Ok(self)
        } else {
            let status = self.status();
            match self.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }

    async fn or_status_error_opt(self) -> Result<Option<Self>, Error> {
        match self.status() {
            StatusCode::OK => Ok(Some(self)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let status = self.status();
                match self.text().await {
                    Ok(body) => Err(Error::Response(status, body)),
                    Err(e) => Err(Error::Request(e)),
                }
            }
        }
    }
}
