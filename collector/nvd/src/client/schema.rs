use crate::client::cvss2::Cvss2Data;
use crate::client::cvss30::Cvss30Data;
use crate::client::cvss31::Cvss31Data;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub cve: Cve,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    #[serde(default)]
    pub source_identifier: Option<String>,
    pub published: NaiveDateTime,
    pub last_modified: NaiveDateTime,
    #[serde(default)]
    pub evaluator_comment: Option<String>,
    #[serde(default)]
    pub evaluator_solution: Option<String>,
    #[serde(default)]
    pub evaluator_impact: Option<String>,
    pub descriptions: Vec<LangString>,
    pub references: Vec<Reference>,
    #[serde(default)]
    pub metrics: Option<Metrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LangString {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub url: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    #[serde(default)]
    pub cvss_metric_v31: Vec<CvssV31>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<CvssV30>,
    #[serde(default)]
    pub cvss_metric_v2: Vec<CvssV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV31 {
    pub source: String,
    pub r#type: String,
    pub cvss_data: Cvss31Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV30 {
    pub source: String,
    pub r#type: String,
    pub cvss_data: Cvss30Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2 {
    pub source: String,
    pub r#type: String,
    pub cvss_data: Cvss2Data,
}
