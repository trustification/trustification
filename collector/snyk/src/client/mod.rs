use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::client::schema::{Issue, Response};

pub mod schema;

#[derive(Debug, derive_more::Display, Serialize, Deserialize)]
pub enum Error {
    #[display(fmt = "HTTP error")]
    Http,
    #[display(fmt = "Serialization error")]
    Serialization,
    #[display(fmt = "Snyk error")]
    Snyk(Vec<schema::Error>),
}

impl std::error::Error for Error {}

struct SnykUrl(&'static str);

impl SnykUrl {
    const fn new(base: &'static str) -> Self {
        Self(base)
    }

    /*
    pub fn batch_issues(&self, org_id: &str) -> Url {
        Url::parse(&format!("{}/orgs/{}/packages/issues", self.0, org_id)).unwrap()
    }
     */

    pub fn issues(&self, org_id: &str, purl: &str) -> Url {
        Url::parse(&format!(
            "{}/orgs/{}/packages/{}/issues",
            self.0,
            org_id,
            url_escape::encode_component(purl),
        ))
        .unwrap()
    }
}

const SNYK_URL: SnykUrl = SnykUrl::new("https://api.snyk.io/rest");

#[derive(Clone, Serialize, Deserialize)]
pub struct IssuesRequest {
    data: IssuesRequestData,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuesRequestData {
    attributes: IssuesRequestAttributes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IssuesRequestAttributes {
    purls: Vec<String>,
}

pub struct SnykClient {
    org_id: String,
    token: String,
    client: reqwest::Client,
}

impl SnykClient {
    pub fn new(org_id: &str, token: &str) -> Self {
        Self {
            org_id: org_id.to_string(),
            token: token.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /*
    pub async fn batch_issues(&self, purls: Vec<String>) -> Result<(), anyhow::Error> {
        println!("{}", SNYK_URL.batch_issues(&self.org_id));
        let result: serde_json::Map<_, _> = reqwest::Client::new()
            .post(SNYK_URL.batch_issues(&self.org_id))
            .header("Authorization", format!("token {}", &self.token))
            .header("Content-Type", "application/vnd.api+json")
            .query(&[("version", "2023-08-31~beta")])
            .json(&IssuesRequest {
                data: IssuesRequestData {
                    attributes: IssuesRequestAttributes {
                        purls
                    }
                }
            })
            .send()
            .await?
            .json()
            .await?;

        println!("{:#?}", result);

        Ok(())
    }
     */

    pub async fn issues(&self, purl: &str) -> Result<Vec<Issue>, Error> {
        let result: Response<Vec<Issue>> = self
            .client
            .get(SNYK_URL.issues(&self.org_id, purl))
            .header("Authorization", format!("token {}", &self.token))
            .header("Content-Type", "application/vnd.api+json")
            .query(&[("version", "2023-08-31~beta")])
            .send()
            .await
            .map_err(|_| Error::Http)?
            .json()
            .await
            .map_err(|_| Error::Serialization)?;

        if let Some(issues) = result.data {
            Ok(issues)
        } else {
            Err(Error::Snyk(result.errors.unwrap_or(vec![])))
        }
    }
}

#[cfg(test)]
mod test {

    use crate::client::SnykClient;

    pub fn client() -> Result<SnykClient, anyhow::Error> {
        let org_id = std::env::var("SNYK_ORG_ID")?;
        let token = std::env::var("SNYK_TOKEN")?;

        Ok(SnykClient::new(&org_id, &token))
    }

    /*
    #[test_with::env(SNYK_ORG_ID,SNYK_TOKEN)]
    #[tokio::test]
    async fn batch() -> Result<(), anyhow::Error> {
        client()?
            .batch_issues(vec!["pkg:maven/org.apache.logging.log4j/log4j-core@2.13.3".to_string()])
            .await?;
        Ok(())
    }

     */

    #[test_with::env(SNYK_ORG_ID, SNYK_TOKEN)]
    #[tokio::test]
    async fn single() -> Result<(), anyhow::Error> {
        client()?
            .issues("pkg:maven/org.apache.logging.log4j/log4j-core@2.13.3")
            .await?;
        Ok(())
    }
}
