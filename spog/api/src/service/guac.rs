use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;

use actix_web::{http::header::ContentType, HttpResponse};
use guac::client::intrinsic::certify_vex_statement::{CertifyVexStatement, CertifyVexStatementSpec, VexStatus};
use guac::client::intrinsic::certify_vuln::{CertifyVuln, CertifyVulnSpec};
use guac::client::intrinsic::package::Package;
use guac::client::intrinsic::vuln_equal::{VulnEqual, VulnEqualSpec};
use guac::client::intrinsic::vuln_metadata::{VulnerabilityMetadata, VulnerabilityMetadataSpec};
use guac::client::intrinsic::vulnerability::{Vulnerability, VulnerabilitySpec};
use guac::client::{Error as GuacError, GuacClient};
use http::StatusCode;
use packageurl::PackageUrl;
use tracing::instrument;

use spog_model::prelude::{
    CveDetails, PackageDependencies, PackageDependents, PackageRefList, PackageRelatedToProductCve, ProductCveStatus,
    ProductRelatedToPackage,
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

    #[error("Client error: {0}")]
    Client(String),
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
            &Error::Client(_) => StatusCode::BAD_REQUEST,
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
            Self::PurlFormat(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Purl parsing error".to_string(),
                details: error.to_string(),
            }),
            Self::Client(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Guac client error".to_string(),
                details: error.to_string(),
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

    pub fn with_client(url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            client: GuacClient::with_client(url.into(), client),
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

    #[instrument(skip(self, purl), fields(purl = %purl), ret, err)]
    pub async fn certify_vex(&self, purl: &str) -> Result<Vec<CertifyVexStatement>, Error> {
        let purl = PackageUrl::from_str(purl)?;
        Ok(self
            .client
            .intrinsic()
            .certify_vex_statement(&CertifyVexStatementSpec {
                subject: Some(purl.clone().into()),
                status: Some(VexStatus::Affected),
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
    fn get_purl(&self, package: Package) -> Result<PackageUrl<'_>, Error> {
        let purls = package.try_as_purls()?;
        if purls.is_empty() {
            Err(Error::Client(format!("Cannot parse package {:?}", package).to_string()))
        } else {
            Ok(purls[0].clone())
        }
    }

    /// Find SBOMs affected by CVE
    /// The result contains affected packages grouped by sbom and status.
    ///
    /// The `id` is an identifier for an CVE.
    ///
    /// The result is `map<status, map<sbom_id, vec<package>>`.
    #[instrument(skip(self), err)]
    pub async fn product_by_cve(&self, id: String) -> Result<CveDetails, Error> {
        let result = self.client.semantic().product_by_cve(&id).await?;
        let mut products = BTreeMap::<ProductCveStatus, BTreeMap<String, Vec<PackageRelatedToProductCve>>>::new();

        for product in result {
            let root = self.get_purl(product.root)?.clone();

            let sbom = self.client.intrinsic().has_sbom(&root.clone().into()).await?;
            if sbom.is_empty() {
                return Err(Error::Client(format!("Cannot find an SBOM for {:?}", root).to_string()));
            }
            let uid = &sbom[0].uri;

            let status = match product.vex.status {
                VexStatus::Affected => Ok(ProductCveStatus::KnownAffected),
                VexStatus::Fixed => Ok(ProductCveStatus::Fixed),
                VexStatus::UnderInvestigation => Ok(ProductCveStatus::UnderInvestigation),
                VexStatus::NotAffected => Ok(ProductCveStatus::KnownNotAffected),
                VexStatus::Other(_) => Err(Error::Client(
                    format!("Cannot process CVE {}, unknown status {:?}", uid, product.vex.status).to_string(),
                )),
            };

            let cves = products.entry(status?).or_default();

            let packages = cves.entry(uid.to_string()).or_default();

            for package in product.path {
                let p = self.get_purl(package)?.to_string();
                packages.push(PackageRelatedToProductCve {
                    purl: p,
                    r#type: "Direct".to_string(), // TODO support transient dependencies
                })
            }
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
    #[instrument(skip(self), err)]
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

    /// Find vulnerabilities for an SBOM (by SBOM UID)
    ///
    /// The result is `map<cve, set<purls>>`.
    #[instrument(skip(self), err)]
    pub async fn find_vulnerability_by_uid(
        &self,
        id: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<HashMap<String, BTreeSet<String>>, Error> {
        Ok(self
            .client
            .semantic()
            .find_vulnerability_by_sbom_uri(id, offset, limit)
            .await?)
    }

    #[instrument(skip(self), err)]
    pub async fn product_by_package(
        &self,
        purl: &str,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<ProductRelatedToPackage>, Error> {
        let products = self
            .client
            .semantic()
            .find_dependent_product(purl, offset, limit)
            .await?;
        Ok(products
            .iter()
            .map(|sbom_id| ProductRelatedToPackage {
                sbom_uid: sbom_id.to_string(),
                backtraces: vec![],
            })
            .collect::<Vec<ProductRelatedToPackage>>())
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
        let res = guac.product_by_cve("cve-2023-2976".to_string()).await.unwrap();
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

    // TODO do proper testing
    // Use ds1 dataset
    #[tokio::test]
    #[ignore]
    async fn test_product_by_package() {
        let guac = GuacService::new("http://localhost:8085/query");
        let res = guac.product_by_package("pkg:maven/org.xerial.snappy/snappy-java@1.1.8.4-redhat-00003?repository_url=https://maven.repository.redhat.com/ga/&type=jar", None, None).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
    }
}
