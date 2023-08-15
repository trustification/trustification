use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::GuacClient;
use http::StatusCode;
use spog_model::prelude::{PackageDependencies, PackageDependents, PackageList};
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

    /// Lookup related packages for a provided Package URL
    pub async fn get_packages(&self, purl: &str) -> Result<PackageList, Error> {
        let pkgs = self.client.get_packages(purl).await.map_err(Error::Guac)?;
        Ok(PackageList::from(pkgs))
    }

    /// Lookup dependencies for a provided Package URL
    pub async fn get_dependencies(&self, purl: &str) -> Result<PackageDependencies, Error> {
        let deps = self.client.is_dependency(purl).await.map_err(Error::Guac)?;
        Ok(PackageDependencies::from(deps))
    }

    /// Lookup dependents for a provided Package URL
    pub async fn get_dependents(&self, purl: &str) -> Result<PackageDependents, Error> {
        let deps = self.client.is_dependent(purl).await.map_err(Error::Guac)?;
        Ok(PackageDependents::from(deps))
    }
}
