use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;

use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::intrinsic::certify_vex_statement::VexStatus;
use guac::client::intrinsic::certify_vuln::{CertifyVuln, CertifyVulnSpec};
use guac::client::intrinsic::vuln_equal::{VulnEqual, VulnEqualSpec};
use guac::client::intrinsic::vuln_metadata::{VulnerabilityMetadata, VulnerabilityMetadataSpec};
use guac::client::intrinsic::vulnerability::{Vulnerability, VulnerabilitySpec};
use guac::client::{Error as GuacError, GuacClient};
use http::StatusCode;
use packageurl::PackageUrl;
use tracing::instrument;

use spog_model::prelude::{
    CveDetails, PackageDependencies, PackageDependents, PackageRefList, PackageRelatedToProductCve, ProductCveStatus,
    ProductRelatedToCve,
};
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
    #[instrument(skip(self), err)]
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
    #[instrument(skip(self), err)]
    pub async fn get_dependencies(&self, purl: &str) -> Result<PackageDependencies, Error> {
        let purl = PackageUrl::from_str(purl)?;

        let deps = self.client.semantic().dependencies_of(&purl).await?;

        Ok(PackageDependencies::from(
            deps.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        ))
    }

    /// Lookup dependents for a provided Package URL
    #[instrument(skip(self), err)]
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

    #[instrument(skip(self, purl), fields(purl = %purl), ret, err)]
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

    /// Get metadata for a vulnerability by its ID.
    #[instrument(skip(self), ret, err)]
    pub async fn vuln_meta(&self, id: String) -> Result<Vec<VulnerabilityMetadata>, Error> {
        Ok(self
            .client
            .intrinsic()
            .vuln_metadata(&VulnerabilityMetadataSpec {
                id: Some(id),
                ..Default::default()
            })
            .await?)
    }

    /// Get aliases of a vulnerability
    #[instrument(skip(self), ret, err)]
    pub async fn vuln_aliases(&self, id: String) -> Result<Vec<VulnEqual>, Error> {
        Ok(self
            .client
            .intrinsic()
            .vuln_equal(&VulnEqualSpec {
                id: Some(id),
                ..Default::default()
            })
            .await?)
    }

    #[instrument(skip(self), err)]
    pub async fn product_by_cve(&self, id: String) -> Result<CveDetails, Error> {
        let result = self.client.semantic().product_by_cve(&id).await?;
        let mut products = BTreeMap::<ProductCveStatus, Vec<ProductRelatedToCve>>::new();

        for product in result {
            let id = product.root.try_as_purls()?[0].name().to_string();

            let mut packages: Vec<PackageRelatedToProductCve> = Vec::new();

            for package in product.path {
                let p = package.try_as_purls()?[0].to_string();
                packages.push(PackageRelatedToProductCve {
                    purl: p,
                    r#type: "Direct".to_string(),
                })
            }

            let pr = ProductRelatedToCve { sbom_id: id, packages };

            let status = match product.vex.status {
                VexStatus::Affected => ProductCveStatus::KnownAffected,
                VexStatus::Fixed => ProductCveStatus::Fixed,
                VexStatus::UnderInvestigation => ProductCveStatus::UnderInvestigation,
                VexStatus::NotAffected => ProductCveStatus::KnownNotAffected,
                VexStatus::Other(_) => todo!(),
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

    /// Find vulnerabilities for an SBOM
    ///
    /// The `sbom_id` is an identifier for an SBOM. Currently, this is a special PURL format of
    /// `pkg:/guac/pkg/<name>@<version>`, where `<name>` and `<version>` are coming from the single
    /// (expected) "document describes" component.
    ///
    /// Later on, this will be replaced with the SPDX namespace, or the CycloneDX serial.
    ///
    /// The result is `map<cve, set<purls>>`.
    #[instrument(skip(self), ret, err)]
    pub async fn find_vulnerability(
        &self,
        id: GuacSbomIdentifier<'_>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<HashMap<String, BTreeSet<String>>, Error> {
        let purl = PackageUrl::new("guac", id.name)?
            .with_namespace("pkg")
            .with_version(id.version)
            .to_string();

        log::debug!("Using GUAC purl: {purl}");

        Ok(self.client.semantic().find_vulnerability(&purl, offset, limit).await?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuacSbomIdentifier<'a> {
    pub name: &'a str,
    pub version: &'a str,
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

    // TODO do proper testing
    // ./bin/guacone collect files --gql-addr http://localhost:8085/query ./rhel-7.9.z.json
    // ./bin/guacone collect files --gql-addr http://localhost:8085/query ./cve-2022-2284.json
    #[tokio::test]
    #[ignore]
    async fn test_find_vulnerability() {
        let guac = GuacService::new("http://localhost:8085/query");
        let res = guac
            .find_vulnerability(
                GuacSbomIdentifier {
                    name: "rhel-7.9.z",
                    version: "7.9.z",
                },
                Some(0),
                Some(20),
            )
            .await
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    }
}
