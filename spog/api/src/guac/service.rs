use std::str::FromStr;

use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::{Error as GuacError, GuacClient};
use http::StatusCode;
use packageurl::PackageUrl;

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

    #[error("Data format error: {0}")]
    PurlFormat(packageurl::Error),
}

impl From<packageurl::Error> for Error {
    fn from(value: packageurl::Error) -> Self {
        Self::PurlFormat(value)
    }
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());
        match self {
            Self::Guac(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", error),
                details: error.to_string(),
            }),
            Self::PurlFormat(err) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Purl parsing error".to_string(),
                details: err.to_string(),
            }),
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::Guac(error) => match error {
                GuacError::Purl(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Error::PurlFormat(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl GuacService {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: GuacClient::new(&url.into()),
        }
    }

    /// Lookup related packages for a provided Package URL
    pub async fn get_packages(&self, purl: &str) -> Result<PackageRefList, Error> {
        let purl = PackageUrl::from_str(purl)?;
        let packages = self.client.intrinsic().packages(&purl.into()).await?;

        let mut pkgs = Vec::new();

        for package in packages {
            let purls = package.try_as_purls()?;
            for purl in purls {
                pkgs.push(purl.to_string())
            }
        }

        Ok(PackageRefList::from(pkgs))
    }

    /// Lookup dependencies for a provided Package URL
    pub async fn get_dependencies(&self, purl: &str) -> Result<PackageDependencies, Error> {
        let purl = PackageUrl::from_str(purl)?;

        let deps = self.client.semantic().dependencies_of(&purl).await?;

        Ok(PackageDependencies::from(
            deps.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        ))
    }

    /// Lookup dependents for a provided Package URL
    pub async fn get_dependents(&self, purl: &str) -> Result<PackageDependents, Error> {
        let purl = PackageUrl::from_str(purl)?;

        let deps = self.client.semantic().dependents_of(&purl).await?;

        Ok(PackageDependencies::from(
            deps.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        ))
    }
}
