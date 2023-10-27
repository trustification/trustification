pub mod components;

use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use trustification_common::error::ErrorInformation;
use url::ParseError;
use yew::html::IntoPropValue;
use yew::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
}

impl IntoPropValue<String> for Error {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}

impl IntoPropValue<String> for &Error {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}

#[async_trait(?Send)]
pub trait ApiErrorForStatus: Sized {
    async fn api_error_for_status(self) -> Result<Self, ApiError>;
}

#[async_trait(?Send)]
impl ApiErrorForStatus for Response {
    async fn api_error_for_status(self) -> Result<Self, ApiError> {
        let status = self.status();
        if status.is_client_error() || status.is_server_error() {
            match self.text().await {
                Err(_err) => Err(ApiError::new_api(status, ApiErrorDetails::Unknown)),
                Ok(text) => match text.is_empty() {
                    true => Err(ApiError::new_api(status, ApiErrorDetails::Empty)),
                    false => match serde_json::from_str(&text) {
                        Ok(info) => Err(ApiError::new_api(status, ApiErrorDetails::Information(info))),
                        Err(_) => Err(ApiError::new_api(status, ApiErrorDetails::Plain(text))),
                    },
                },
            }
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiErrorDetails {
    Information(ErrorInformation),
    Plain(String),
    Empty,
    Unknown,
}

impl std::fmt::Display for ApiErrorDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Information(info) => {
                write!(f, "{} ({})", info.message, info.error)
            }
            Self::Plain(s) => f.write_str(s),
            Self::Empty => f.write_str("no information"),
            Self::Unknown => f.write_str("unknown error information"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {details} ({status})")]
    Api {
        status: StatusCode,
        details: ApiErrorDetails,
    },
}

impl ApiError {
    pub fn new_api(status: StatusCode, details: ApiErrorDetails) -> Self {
        Self::Api { status, details }
    }

    pub fn to_html(&self, title: impl Into<AttrValue>) -> Html {
        use components::Error;

        match self {
            ApiError::Api {
                status: _,
                details: ApiErrorDetails::Information(info),
            } => {
                html!(
                    <Error title={title.into()} message={info.message.clone()} err={info.details.clone()}/>
                )
            }
            _ => html!(<Error title={title.into()} message="Error processing request" err={self} />),
        }
    }
}

impl IntoPropValue<String> for ApiError {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}

impl IntoPropValue<String> for &ApiError {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}
