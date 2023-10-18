use std::collections::BTreeMap;
use std::str::FromStr;

use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::intrinsic::certify_vex::VexStatus;
use guac::client::intrinsic::certify_vuln::{CertifyVuln, CertifyVulnSpec};
use guac::client::intrinsic::vulnerability::{Vulnerability, VulnerabilitySpec};
use guac::client::{Error as GuacError, GuacClient};
use http::StatusCode;
use packageurl::PackageUrl;
use tracing::instrument;

use spog_model::prelude::{PackageDependencies, PackageDependents, PackageRefList, ProductCveStatus, ProductRelatedToCve, PackageRelatedToProductCve, CveDetails};
use trustification_common::error::ErrorInformation;

#[derive(Clone)]
pub struct GuacService {
    pub client: GuacClient,
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
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Guac(error) => match error {
                GuacError::Purl(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Error::PurlFormat(_) => StatusCode::BAD_REQUEST,
        }
    }

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

    #[allow(unused)]
    pub async fn affected_cve(&self, id: String) -> Result<Vec<Vulnerability>, Error> {
        Ok(self
            .client
            .intrinsic()
            .vulnerabilities(&VulnerabilitySpec {
                id: None,
                no_vuln: None,
                vulnerability_id: Some(id),
                r#type: None,
            })
            .await?)
    }

    #[instrument(skip(self), err)]
    pub async fn certify_vuln(&self, purl: PackageUrl<'_>) -> Result<Vec<CertifyVuln>, Error> {
        Ok(self
            .client
            .intrinsic()
            .certify_vuln(&CertifyVulnSpec {
                package: Some(purl.into()),
                ..Default::default()
            })
            .await?)
    }

    pub async fn product_by_cve(&self, id: String) -> Result<CveDetails, Error> {
        let result = self.client.intrinsic().product_by_cve(&id).await;
        let data = match result {
            Ok(res) => {
                res
            },
            Err(_err) => {
                // TODO filter error
                Vec::new()
            }
        };
        let mut products = BTreeMap::<ProductCveStatus, Vec<ProductRelatedToCve>>::new();

        for product in data {
            let id = product.root.try_as_purls()?[0].name().to_string();

            let mut packages: Vec<PackageRelatedToProductCve> = Vec::new();

            for package in product.path {
                let p = package.try_as_purls()?[0].to_string();
                packages.push(PackageRelatedToProductCve { purl: p, r#type: "Direct".to_string() })
            }

            let pr = ProductRelatedToCve {
                sbom_id: id,
                packages,
            };

            let status = match product.vex.status {
                VexStatus::Affected => {
                    ProductCveStatus::KnownAffected
                },
                VexStatus::Fixed => {
                    ProductCveStatus::Fixed
                },
                VexStatus::UnderInvestigation => {
                    ProductCveStatus::UnderInvestigation
                },
                VexStatus::NotAffected => {
                    ProductCveStatus::KnownNotAffected
                }
            };

            products.entry(status).or_insert(vec![]).push(pr);
        }

        Ok(CveDetails {
            id,
            products,
            details: vec![],
            advisories: vec![],
        })
    }

}

#[cfg(test)]
mod test {
    use super::*;

    // TODO do proper testing
    // ./bin/guacone collect files --gql-addr http://localhost:8085/query ./rhel-7.9.z.json
    // ./bin/guacone collect files --gql-addr http://localhost:8085/query ./cve-2022-2284.json
    #[tokio::test]
    #[ignore]
    async fn test_product_by_cve() {
        let guac = GuacService::new("http://localhost:8085/query");
        let res = guac.product_by_cve("cve-2022-2284".to_string()).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    }

}