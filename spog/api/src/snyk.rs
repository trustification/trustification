use snyk::apis::configuration::{self, ApiKey};

use crate::package::{ApiError, VulnerabilityRef};
use crate::Snyk;

pub async fn get_vulnerabilities(snyk: Snyk, purl: &str) -> Result<Vec<VulnerabilityRef>, anyhow::Error> {
    let mut ret = Vec::new();
    if snyk.org.is_some() && snyk.token.is_some() {
        let key = ApiKey {
            prefix: Some("token".to_string()),
            key: snyk.token.as_ref().ok_or(ApiError::InternalError)?.to_string(),
        };

        let config = configuration::Configuration {
            api_key: Some(key),
            ..Default::default()
        };
        let issues = snyk::apis::issues_api::fetch_issues_per_purl(
            &config,
            "2023-02-15",
            purl,
            snyk.org.as_ref().ok_or(ApiError::InternalError)?,
            None,
            None,
        )
        .await;

        if let Ok(issue) = issues {
            if let Some(data) = issue.data {
                for d in data {
                    if let Some(id) = d.id {
                        let vuln_ref = VulnerabilityRef {
                            cve: id.clone(),
                            href: format!("{}/{}", "https://security.snyk.io/vuln", id),
                        };
                        if !ret.contains(&vuln_ref) {
                            ret.push(vuln_ref);
                        }
                    }
                }
            };
        }
    }
    Ok(ret)
}
