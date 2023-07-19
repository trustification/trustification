pub mod schema;

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

//#[derive(Serialize, Deserialize)]
//pub struct Package {
//purl: String,
//}

/*
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryResponse {
    Vulnerabilities { vulns: Vec<Vulnerability> },
    NoResult(serde_json::Value),
}
 */

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryBatchResponse {
    results: Vec<BatchVulnerabilities>,
}

#[derive(Debug, Serialize, Deserialize)]
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

        let results: Vec<_> = request.queries.iter().zip(response.results.iter()).map( |(req, resp)| {
            if resp.vulns.is_some() {
                println!("##############################################################################################");
                println!("##############################################################################################");
                println!("##############################################################################################");
                println!("##############################################################################################");
                println!("{:?}", req.package);

            }
            CollatedBatchVulnerabilities {
                package: req.package.clone(),
                vulns: resp.vulns.clone(),
            }
        }).collect();

        let response = CollatedQueryBatchResponse { results };

        Ok(response)
    }
    /*
    pub async fn query(request: &GatherRequest) -> Result<GatherResponse, anyhow::Error> {
        let requests: Vec<_> = request
            .purls
            .iter()
            .map(|purl| {
                let json_body = serde_json::to_string(&QueryPackageRequest {
                    package: Package { purl: purl.clone() },
                })
                .ok()
                .unwrap_or("".to_string());

                async move {
                    (
                        purl.clone(),
                        reqwest::Client::new()
                            .post(QUERY_URL)
                            .json(&QueryPackageRequest {
                                package: Package { purl: purl.clone() },
                            })
                            .send()
                            .await,
                    )
                }
            })
            .collect();

        let responses = join_all(requests).await;

        let mut purls = Vec::new();
        for (purl, response) in responses {
            if let Ok(response) = response {
                let response: Result<QueryResponse, _> = response.json().await;
                if let Ok(response) = response {
                    println!("{:?}", response);
                }
                purls.push(purl);
            } else {
                println!("bogus");
            }
        }

        Ok(GatherResponse {
            purls,
        })

        //println!("{:?}", results);
    }
     */
}
