pub mod components;

use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::rc::Rc;
use trustification_common::error::ErrorInformation;
use url::ParseError;
use yew::html::IntoPropValue;

#[async_trait(?Send)]
pub trait ApiErrorForStatus: Sized {
    async fn api_error_for_status(self) -> Result<Self, ApiError>;
}

fn from_text<E>(status: StatusCode, body: Result<String, E>) -> ApiError {
    match body {
        Err(_) => ApiErrorKind::new_api(status, ApiErrorDetails::Unknown).into(),
        Ok(text) => match text.is_empty() {
            true => ApiErrorKind::new_api(status, ApiErrorDetails::Empty).into(),
            false => match serde_json::from_str(&text) {
                Ok(info) => ApiErrorKind::new_api(status, ApiErrorDetails::Information(info)).into(),
                Err(_) => ApiErrorKind::new_api(status, ApiErrorDetails::Plain(text)).into(),
            },
        },
    }
}

#[async_trait(?Send)]
impl ApiErrorForStatus for Response {
    async fn api_error_for_status(self) -> Result<Self, ApiError> {
        let status = self.status();
        if status.is_client_error() || status.is_server_error() {
            Err(from_text(status, self.text().await))
        } else {
            Ok(self)
        }
    }
}

#[async_trait(?Send)]
impl ApiErrorForStatus for gloo_net::http::Response {
    async fn api_error_for_status(self) -> Result<Self, ApiError> {
        if self.ok() {
            Ok(self)
        } else {
            Err(from_text(
                StatusCode::from_u16(self.status()).unwrap_or(StatusCode::IM_A_TEAPOT),
                self.text().await,
            ))
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

impl Display for ApiErrorDetails {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

#[derive(Clone, Debug)]
pub struct ApiError(Rc<ApiErrorKind>);

impl Deref for ApiError {
    type Target = ApiErrorKind;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! to_api_error {
    ($t:ty) => {
        impl From<$t> for ApiError {
            fn from(value: $t) -> Self {
                Self(Rc::new(value.into()))
            }
        }
    };
}

to_api_error!(ParseError);
to_api_error!(reqwest::Error);
to_api_error!(serde_json::Error);
to_api_error!(gloo_net::Error);

impl PartialEq for ApiError {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl From<ApiErrorKind> for ApiError {
    fn from(value: ApiErrorKind) -> Self {
        Self(Rc::new(value))
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiErrorKind {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Failed to request: {0}")]
    GlooNet(#[from] gloo_net::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {details} ({status})")]
    Api {
        status: StatusCode,
        details: ApiErrorDetails,
    },
}

impl ApiErrorKind {
    pub fn new_api(status: StatusCode, details: ApiErrorDetails) -> Self {
        Self::Api { status, details }
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
