use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;

#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct AdvisorySummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub snippet: String,
    pub desc: String,
    pub date: OffsetDateTime,
    pub cves: Vec<String>,
    pub cvss_max: Option<f64>,
    pub href: String,
    pub cve_severity_count: HashMap<String, u64>,

    #[serde(default, skip_serializing_if = "Value::is_null", rename = "$metadata")]
    pub metadata: Value,
}

#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct CveSummary {
    pub id: String,
    pub title: String,
    pub desc: String,
    pub release: OffsetDateTime,
    pub cvss: Option<f64>,
    pub snippet: String,
    pub advisories: Vec<String>,
}

#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct SbomSummary {
    pub id: String,
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub sha256: String,
    pub license: String,
    pub snippet: String,
    pub classifier: String,
    pub description: String,
    pub supplier: String,
    pub dependencies: u64,
    pub href: String,
    pub advisories: Option<u64>,
    pub created: OffsetDateTime,
    pub vulnerabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Value::is_null", rename = "$metadata")]
    pub metadata: Value,
}

impl SbomSummary {
    pub fn advisories_query(&self) -> Option<String> {
        let mut terms = Vec::new();
        if let Some(cpe) = &self.cpe {
            terms.push(format!("fixed:\"{}\" OR affected:\"{}\"", cpe, cpe));
        }

        if let Some(purl) = &self.purl {
            terms.push(format!("fixed:\"{}\" OR affected:\"{}\"", purl, purl));
        }

        match terms.is_empty() {
            true => None,
            false => Some(terms.join(" OR ")),
        }
    }
}
