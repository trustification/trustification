use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::pkg::PackageRef;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Vulnerability {
    cve: "cve-2023-0286".to_string(),
    summary: "There is a type confusion vulnerability...".to_string(),
    severity: Some("Important".to_string()),
    advisory: "https://access.redhat.com/security/cve/cve-2023-0286".to_string(),
    date: None,
    cvss3: Some(Cvss3 {
        score: "7.4".to_string(),
        status: "verified".to_string(),
    }),
    packages: vec![PackageRef {
        purl: "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string(),
        href: format!("/api/package?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6")),
        trusted: Some(true),
        sbom: None,
    }
]
}))]
pub struct Vulnerability {
    pub cve: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss3: Option<Cvss3>,
    pub summary: String,
    pub advisory: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<PackageRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Cvss3{
score: "7.3".to_string(),
status: "verified".to_string()
}))]
pub struct Cvss3 {
    pub score: String,
    pub status: String,
}
