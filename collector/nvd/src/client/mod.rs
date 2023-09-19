use reqwest::Url;

use crate::client::schema::{QueryResponse, Vulnerability};

pub mod cvss2;
pub mod cvss30;
pub mod cvss31;
pub mod schema;

pub struct NvdUrl(&'static str);

impl NvdUrl {
    const fn new(base: &'static str) -> Self {
        Self(base)
    }

    fn url(&self) -> Url {
        Url::parse(self.0).unwrap()
    }
}

const NVD_URL: NvdUrl = NvdUrl::new("https://services.nvd.nist.gov/rest/json/cves/2.0");

pub struct NvdClient {
    api_key: String,
    client: reqwest::Client,
}

impl NvdClient {
    pub fn new(api_token: &str) -> Self {
        Self {
            api_key: api_token.to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<Vulnerability>, anyhow::Error> {
        let response = self
            .client
            .get(NVD_URL.url())
            .header("apiKey", &self.api_key)
            .query(&[("cveId", cve_id)])
            .send()
            .await?;

        if response.status() != 200 {
            return Ok(None);
        }

        let mut response: QueryResponse = response.json().await?;

        Ok(response.vulnerabilities.pop())
    }
}

#[cfg(test)]
mod test {
    use crate::client::NvdClient;

    pub fn client() -> Result<NvdClient, anyhow::Error> {
        let api_key = std::env::var("NVD_API_KEY")?;

        Ok(NvdClient::new(&api_key))
    }

    #[test_with::env(NVD_API_KEY)]
    #[tokio::test]
    async fn get_valid() -> Result<(), anyhow::Error> {
        let vuln = client()?.get_cve("CVE-2019-1010218").await?;

        assert!(vuln.is_some());
        Ok(())
    }

    #[test_with::env(NVD_API_KEY)]
    #[tokio::test]
    async fn get_invalid() -> Result<(), anyhow::Error> {
        let vuln = client()?.get_cve("CVE-NOT-2019-1010218").await?;
        assert!(vuln.is_none());
        Ok(())
    }
}
