use std::collections::HashMap;

use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};

use collector_client::CollectPackagesResponse;

use crate::client::schema::{BatchVulnerability, Package, Vulnerability};

pub mod schema;

struct OsvUrl(&'static str);

impl OsvUrl {
    const fn new(base: &'static str) -> Self {
        Self(base)
    }

    pub fn querybatch(&self) -> impl IntoUrl {
        format!("{}/querybatch", self.0)
    }

    pub fn vuln(&self, vuln_id: &str) -> impl IntoUrl {
        format!("{}/vulns/{}", self.0, vuln_id)
    }
}

const OSV_URL: OsvUrl = OsvUrl::new("https://api.osv.dev/v1");

pub struct OsvClient {}

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

#[allow(unused)]
impl OsvClient {
    pub async fn query_batch(request: QueryBatchRequest) -> Result<CollatedQueryBatchResponse, anyhow::Error> {
        let response: QueryBatchResponse = reqwest::Client::new()
            .post(OSV_URL.querybatch())
            .json(&request)
            .send()
            .await?
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

    pub async fn vulns(id: &str) -> Result<Vulnerability, anyhow::Error> {
        Ok(reqwest::Client::new()
            .get(OSV_URL.vuln(id))
            .send()
            .await?
            .json()
            .await?)
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
        Self { purls }
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
        let vuln = OsvClient::vulns("GHSA-7rjr-3q55-vv33").await?;
        let _vuln: v11y_client::Vulnerability = vuln.into();

        Ok(())
    }
}
