pub mod schema;

use std::collections::HashMap;

use collector_client::GatherResponse;
use serde::{Deserialize, Serialize};

use crate::client::schema::{BatchVulnerability, Package};

//const QUERY_URL: &str = "https://api.osv.dev/v1/query";
const QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
//const VULNS_URL: &str = "https://api.osv.dev/v1/vulns";

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

impl OsvClient {
    pub async fn query_batch(request: QueryBatchRequest) -> Result<CollatedQueryBatchResponse, anyhow::Error> {
        let response: QueryBatchResponse = reqwest::Client::new()
            .post(QUERYBATCH_URL)
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
}

impl From<CollatedQueryBatchResponse> for GatherResponse {
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
        let tgt = GatherResponse::from(src);
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
        let tgt = GatherResponse::from(src);
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
        let tgt = GatherResponse::from(src);
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
        let tgt = GatherResponse::from(src);
        assert!(!tgt.purls.is_empty());
        assert_eq!(tgt.purls["pkg:foo"], vec!["cve"]);
    }
}
