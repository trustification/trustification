use std::collections::HashMap;

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use url::ParseError;

use collector_client::CollectPackagesResponse;

use crate::client::schema::{BatchVulnerability, Package, Vulnerability};

pub mod schema;

pub struct OsvUrl(&'static str);

impl OsvUrl {
    const fn new(base: &'static str) -> Self {
        Self(base)
    }

    pub fn querybatch(&self) -> Result<Url, url::ParseError> {
        Url::parse(&format!("{}/querybatch", self.0))
    }

    pub fn vuln(&self, vuln_id: &str) -> Result<Url, url::ParseError> {
        Url::parse(&format!("{}/vulns/{}", self.0, vuln_id))
    }
}

pub const OSV_URL: OsvUrl = OsvUrl::new("https://api.osv.dev/v1");

#[derive(Clone, Debug)]
pub struct OsvClient {
    client: reqwest::Client,
}

#[derive(Serialize, Deserialize)]
pub struct QueryPackageRequest {
    pub package: Package,
}

#[derive(Serialize, Deserialize)]
pub struct QueryBatchRequest {
    pub queries: Vec<QueryPackageRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryBatchResponse {
    results: Vec<BatchVulnerabilities>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CollatedQueryBatchResponse {
    pub results: Vec<CollatedBatchVulnerabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVulnerabilities {
    pub vulns: Option<Vec<BatchVulnerability>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CollatedBatchVulnerabilities {
    pub package: Package,
    pub vulns: Option<Vec<BatchVulnerability>>,
}

pub enum Error {
    Url(url::ParseError),
    Http(reqwest::Error),
}

impl From<reqwest::Error> for Error {
    fn from(inner: reqwest::Error) -> Self {
        Self::Http(inner)
    }
}

impl From<url::ParseError> for Error {
    fn from(inner: ParseError) -> Self {
        Self::Url(inner)
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        OsvClient::new()
    }
}

#[allow(unused)]
impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .connection_verbose(true)
                .build()
                .expect("OsvClient should have been created using ClientBuilder::build()"),
        }
    }

    pub async fn query_batch(&self, request: QueryBatchRequest) -> Result<CollatedQueryBatchResponse, Error> {
        if request.queries.is_empty() {
            return Ok(CollatedQueryBatchResponse::default());
        }
        let response: QueryBatchResponse = self
            .client
            .post(OSV_URL.querybatch()?)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let results: Vec<_> = request
            .queries
            .iter()
            .zip(response.results.iter())
            .map(|(req, resp)| CollatedBatchVulnerabilities {
                package: req.package.clone(),
                vulns: resp.vulns.clone(),
            })
            .collect();

        let response = CollatedQueryBatchResponse { results };

        Ok(response)
    }

    pub async fn vulns(&self, id: &str) -> Result<Option<Vulnerability>, anyhow::Error> {
        let response = self.client.get(OSV_URL.vuln(id)?).send().await?;

        match response.status() {
            StatusCode::NOT_FOUND => Ok(None),
            _ => Ok(response.error_for_status()?.json().await?),
        }
    }
}

impl From<CollatedQueryBatchResponse> for CollectPackagesResponse {
    fn from(response: CollatedQueryBatchResponse) -> Self {
        let purls: HashMap<_, _> = response
            .results
            .iter()
            .flat_map(|e| match (&e.package, &e.vulns) {
                (Package::Purl { purl }, Some(v)) if !v.is_empty() => {
                    Some((purl.clone(), v.iter().map(|x| x.id.clone()).collect()))
                }
                _ => None,
            })
            .collect();
        Self {
            purls,
            errors: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response() {
        let src = CollatedQueryBatchResponse::default();
        let tgt = CollectPackagesResponse::from(src);
        assert!(tgt.purls.is_empty());
    }

    #[test]
    fn no_vulns() {
        let src = CollatedQueryBatchResponse {
            results: vec![CollatedBatchVulnerabilities {
                package: Package::Purl {
                    purl: "pkg:foo".to_string(),
                },
                vulns: None,
            }],
        };
        let tgt = CollectPackagesResponse::from(src);
        assert!(tgt.purls.is_empty());
    }

    #[test]
    fn empty_vulns() {
        let src = CollatedQueryBatchResponse {
            results: vec![CollatedBatchVulnerabilities {
                package: Package::Purl {
                    purl: "pkg:foo".to_string(),
                },
                vulns: Some(vec![]),
            }],
        };
        let tgt = CollectPackagesResponse::from(src);
        assert!(tgt.purls.is_empty());
    }

    #[test]
    fn some_vulns() {
        let src = CollatedQueryBatchResponse {
            results: vec![CollatedBatchVulnerabilities {
                package: Package::Purl {
                    purl: "pkg:foo".to_string(),
                },
                vulns: Some(vec![BatchVulnerability {
                    id: "cve".to_string(),
                    modified: Default::default(),
                }]),
            }],
        };
        let tgt = CollectPackagesResponse::from(src);
        assert!(!tgt.purls.is_empty());
        assert_eq!(tgt.purls["pkg:foo"], vec!["cve"]);
    }

    #[tokio::test]
    async fn query_vuln() -> Result<(), anyhow::Error> {
        let vuln = OsvClient::new().vulns("GHSA-7rjr-3q55-vv33").await?.unwrap();

        //println!("#{:#?}", vuln);
        let _vuln: v11y_client::Vulnerability = vuln.into();

        Ok(())
    }

    // https://issues.redhat.com/browse/TC-1714
    #[tokio::test]
    async fn query_vuln_ecosystem_ubuntu() -> Result<(), anyhow::Error> {
        let osv_client = OsvClient::new();
        // these three CVEs ensure full coverage (at commit date) of the Ubuntu Ecosystem
        let _vuln: v11y_client::Vulnerability = osv_client.vulns("CVE-2024-40907").await?.unwrap().into();
        let _vuln: v11y_client::Vulnerability = osv_client.vulns("CVE-2024-7264").await?.unwrap().into();
        let _vuln: v11y_client::Vulnerability = osv_client.vulns("CVE-2024-4764").await?.unwrap().into();

        Ok(())
    }
}
