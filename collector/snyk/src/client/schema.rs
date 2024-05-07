use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<Inner> {
    pub errors: Option<Vec<Error>>,
    pub data: Option<Inner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub id: String,
    pub status: String,
    pub code: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub attributes: IssueAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueAttributes {
    pub key: String,
    pub coordinates: Vec<Coordinates>,
    pub created_at: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub effective_severity_level: Option<String>,
    pub problems: Vec<Problem>,
    pub severities: Vec<Severity>,
    pub slots: Option<Slot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinates {
    pub remedies: Vec<Remedy>,
    pub representation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remedy {
    pub description: Option<String>,
    pub details: Option<RemedyDetails>,
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemedyDetails {
    pub upgrade_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    pub disclosed_at: Option<DateTime<Utc>>,
    pub discovered_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub id: String,
    pub source: String,
    pub url: Option<Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Severity {
    pub level: Option<String>,
    pub score: Option<f32>,
    pub source: String,
    pub vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub disclosure_time: Option<DateTime<Utc>>,
    pub publication_time: Option<DateTime<Utc>>,
    pub updated_time: Option<DateTime<Utc>>,
    pub exploit: Option<String>,
    pub references: Vec<Reference>,
    pub title: Option<String>,
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub title: Option<String>,
    pub url: Option<String>,
}
