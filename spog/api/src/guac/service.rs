use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::{Error as GuacError, GuacClient};
use http::StatusCode;
use spog_model::prelude::{PackageDependencies, PackageDependents, PackageRefList};
use trustification_common::error::ErrorInformation;

#[derive(Clone)]
pub struct GuacService {
    client: GuacClient,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Guac error: {0}")]
    Guac(#[from] GuacError),
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());
        match self {
            Self::Guac(error) => match error {
                GuacError::Purl(err) => res.json(ErrorInformation {
                    error: format!("{}", self.status_code()),
                    message: "Purl parsing error".to_string(),
                    details: err.to_string(),
                }),
                GuacError::Http(err) => res.json(ErrorInformation {
                    error: format!("{}", self.status_code()),
                    message: "Purl parsing error".to_string(),
                    details: err.to_string(),
                }),
                GuacError::GraphQL(msg) => res.json(ErrorInformation {
                    error: format!("{}", self.status_code()),
                    message: "Purl parsing error".to_string(),
                    details: msg.to_string(),
                }),
            },
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Guac(error) => match error {
                GuacError::Purl(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }
}

impl GuacService {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: GuacClient::new(url.into()),
        }
    }

    /// Lookup related packages for a provided Package URL
    pub async fn get_packages(&self, purl: &str) -> Result<PackageRefList, Error> {
        let pkgs = self.client.get_packages(purl).await?;
        Ok(PackageRefList::from(pkgs))
    }

    /// Lookup dependencies for a provided Package URL
    pub async fn get_dependencies(&self, purl: &str) -> Result<PackageDependencies, Error> {
        let deps = self.client.is_dependency(purl).await?;
        Ok(PackageDependencies::from(deps))
    }

    /// Lookup dependents for a provided Package URL
    pub async fn get_dependents(&self, purl: &str) -> Result<PackageDependents, Error> {
        let deps = self.client.is_dependent(purl).await?;
        Ok(PackageDependents::from(deps))
    }
}
