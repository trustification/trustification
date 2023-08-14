use actix_web::{HttpResponse, http::header::ContentType};
use guac::client::GuacClient;
use http::StatusCode;
use trustification_common::error::ErrorInformation;

#[derive(Clone)]
pub struct GuacService {
    client: GuacClient,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Guac error: {0}")]
    Guac(#[source] anyhow::Error),
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());
        res.json(ErrorInformation {
            error: format!("{}", self.status_code()),
            message: "Error constructing url to backend service".to_string(),
            details: self.to_string(),
        })
    }
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl GuacService {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: GuacClient::new(url.into()),
        }
    }

    /// Lookup dependencies for a provided Package URL
    pub async fn get_dependencies(&self, purl: &str) -> Result<Vec<String>, Error> {
        let deps = self.client.is_dependency(purl).await.map_err(Error::Guac)?;
        Ok(deps)
    }

    /// Lookup dependents for a provided Package URL
    pub async fn get_dependents(&self, purl: &str) -> Result<Vec<String>, Error> {
        let deps = self.client.is_dependent(purl).await.map_err(Error::Guac)?;
        Ok(deps)
    }
}
