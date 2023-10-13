use super::pkg::PackageRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

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

#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SbomReport {
    /// The SBOM name
    pub name: String,
    /// The SBOM version
    pub version: Option<String>,
    /// The time the document was created
    pub created: Option<OffsetDateTime>,

    /// Vulnerabilities summary
    pub summary: Vec<(Option<cvss::Severity>, usize)>,
    /// Vulnerabilities list
    pub details: Vec<SbomReportVulnerability>,
}

#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SbomReportVulnerability {
    pub id: String,
    pub description: String,
    pub score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<OffsetDateTime>,
}
