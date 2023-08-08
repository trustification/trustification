use serde_json::Value;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use time::OffsetDateTime;

#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct AdvisorySummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub snippet: String,
    pub desc: String,
    pub date: time::OffsetDateTime,
    pub cves: Vec<String>,
    pub cvss_max: Option<f64>,
    pub href: String,
    pub cve_severity_count: HashMap<String, u64>,

    #[serde(default, skip_serializing_if = "Value::is_null", rename = "$metadata")]
    pub metadata: Value,
}
/*
#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct VulnSummary {
    pub id: String,
    pub title: String,
    pub desc: String,
    pub release: time::OffsetDateTime,
    pub cvss: Option<f64>,
    pub snippet: String,
    pub advisories: Vec<String>,
}*/

#[derive(utoipa::ToSchema, serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct PackageSummary {
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
    pub dependencies: Vec<String>,
    pub href: String,
    pub advisories: Vec<String>,
    pub created: OffsetDateTime,

    #[serde(default, skip_serializing_if = "Value::is_null", rename = "$metadata")]
    pub metadata: Value,
}

impl PackageSummary {
    pub fn advisories_query(&self) -> String {
        let mut terms = Vec::new();
        if let Some(cpe) = &self.cpe {
            terms.push(format!("fixed:\"{}\" OR affected:\"{}\"", cpe, cpe));
        }

        if let Some(purl) = &self.purl {
            terms.push(format!("fixed:\"{}\" OR affected:\"{}\"", purl, purl));
        }
        terms.join(" OR ")
    }
}

#[derive(utoipa::ToSchema, Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchResult<T> {
    pub result: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

impl<T> SearchResult<T> {
    pub fn map<F, U>(self, f: F) -> SearchResult<U>
    where
        F: FnOnce(T) -> U,
    {
        SearchResult {
            result: f(self.result),
            total: self.total,
        }
    }
}

impl<T> Deref for SearchResult<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

impl<T> DerefMut for SearchResult<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.result
    }
}

impl<T> From<(T, usize)> for SearchResult<T> {
    fn from((result, total): (T, usize)) -> Self {
        Self {
            result,
            total: Some(total),
        }
    }
}
