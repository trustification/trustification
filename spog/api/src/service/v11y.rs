use crate::search::QueryParams;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use reqwest::Response;
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::SearchResult;
use trustification_auth::client::TokenProvider;
use trustification_common::error::ErrorInformation;
use url::Url;
use v11y_client::search::{SearchDocument, SearchHit};
use v11y_client::{V11yClient, Vulnerability};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Any(anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Error::Any(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "V11yError".into(),
                message: "Failed to contact v11y".into(),
                details: err.to_string(),
            }),
        }
    }
}

pub struct V11yService {
    client: V11yClient,
}

impl V11yService {
    pub fn new(client: reqwest::Client, url: Url, provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            client: V11yClient::new(client, url, provider),
        }
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_cve(&self, id: &str) -> Result<Response, Error> {
        self.client.get_cve(id).await.map_err(Error::Any)
    }

    #[instrument(skip(self), err)]
    pub async fn fetch_by_alias(&self, alias: &str) -> Result<Vec<Vulnerability>, Error> {
        self.client.get_vulnerability_by_alias(alias).await.map_err(Error::Any)
    }

    #[instrument(skip(self), err)]
    pub async fn get_cve_status(&self) -> Result<v11y_model::search::StatusResult, Error> {
        self.client.get_cve_status().await.map_err(Error::Any)
    }

    #[instrument(skip(self), err)]
    pub async fn search(&self, query: QueryParams) -> Result<SearchResult<Vec<SearchHit<SearchDocument>>>, Error> {
        self.client
            .search(&query.q, query.limit, query.offset)
            .await
            .map_err(Error::Any)
    }
}
