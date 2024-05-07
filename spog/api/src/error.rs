use crate::service::{collectorist, guac, v11y};
use actix_web::{http::header::ContentType, HttpResponse};
use http::StatusCode;
use trustification_common::error::ErrorInformation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("response error: {0} / {1}")]
    Response(StatusCode, String),
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("authentication error: {0}")]
    AuthClient(#[from] trustification_auth::client::Error),
    #[error("guac error: {0}")]
    Guac(#[from] guac::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::error::Error),
    #[error("collectorist error: {0}")]
    Collectorist(#[from] collectorist::Error),
    #[error("v11y error: {0}")]
    V11y(#[from] v11y::Error),
    #[error(transparent)]
    PackageUrl(#[from] packageurl::Error),
    #[error("{0}")]
    Generic(String),
}

impl actix_web::error::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Response(status, _) => *status,
            Self::PackageUrl(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());
        match self {
            Self::Response(status, error) => res.json(ErrorInformation {
                error: format!("{}", status),
                message: "Error response from backend service".to_string(),
                details: error.to_string(),
            }),
            Self::Request(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error creating request to backend service".to_string(),
                details: error.to_string(),
            }),
            Self::UrlParse(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error constructing url to backend service".to_string(),
                details: error.to_string(),
            }),
            Self::AuthClient(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error creating authentication client".to_string(),
                details: error.to_string(),
            }),
            Self::Serde(error) => res.json(ErrorInformation {
                error: "Serialization".to_string(),
                message: "Serialization error".to_string(),
                details: error.to_string(),
            }),
            Self::Guac(error) => res.json(ErrorInformation {
                error: "Guac".to_string(),
                message: "Error contacting GUAC".to_string(),
                details: error.to_string(),
            }),
            Self::Collectorist(error) => res.json(ErrorInformation {
                error: "collectorist".to_string(),
                message: "Error contacting collectorist".to_string(),
                details: error.to_string(),
            }),
            Self::V11y(error) => res.json(ErrorInformation {
                error: "v11y".to_string(),
                message: "Error contacting v11y".to_string(),
                details: error.to_string(),
            }),
            Self::PackageUrl(error) => res.json(ErrorInformation {
                error: "PackageUrl".to_string(),
                message: "Invalid package URL syntax".to_string(),
                details: error.to_string(),
            }),
            Self::Generic(error) => res.json(ErrorInformation {
                error: "Generic".to_string(),
                message: error.clone(),
                details: error.to_string(),
            }),
        }
    }
}
