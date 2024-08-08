use std::collections::HashMap;

use serde_json::Value;
use sikula::prelude::*;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Vulnerabilities<'a> {
    #[search(default)]
    Id(Primary<'a>),
    #[search(default)]
    Cve(Primary<'a>),
    #[search(default)]
    Title(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    Status(&'a str),
    #[search(sort)]
    Severity(&'a str),
    Cvss(PartialOrdered<f64>),
    #[search(scope)]
    Package(Primary<'a>),
    #[search(scope)]
    Fixed(Primary<'a>),
    #[search(scope)]
    Affected(Primary<'a>),
    #[search(scope)]
    NotAffected(Primary<'a>),
    #[search]
    Initial(Ordered<time::OffsetDateTime>),
    #[search(sort)]
    Release(Ordered<time::OffsetDateTime>),
    #[search]
    CveRelease(Ordered<time::OffsetDateTime>),
    #[search]
    CveDiscovery(Ordered<time::OffsetDateTime>),
    #[search(sort)]
    IndexedTimestamp(Ordered<time::OffsetDateTime>),
    Final,
    Critical,
    High,
    Medium,
    Low,
}

/// A document returned from the search index for every match.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, ToSchema)]
pub struct SearchDocument {
    /// Advisory identifier
    pub advisory_id: String,
    /// Advisory title
    pub advisory_title: String,
    /// Advisory release date in RFC3339 format
    #[schema(value_type = String)]
    pub advisory_date: time::OffsetDateTime,
    /// Snippet highlighting part of description that matched
    pub advisory_snippet: String,
    /// Advisory description
    pub advisory_desc: String,
    /// Advisory severity
    pub advisory_severity: Option<String>,
    /// List of CVE identifiers that matched within the advisory
    pub cves: Vec<String>,
    /// Highest CVSS score in vulnerabilities matched within the advisory
    pub cvss_max: Option<f64>,
    /// Number of severities by level
    pub cve_severity_count: HashMap<String, u64>,
    /// Time stamp for doc
    pub indexed_timestamp: OffsetDateTime,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchHit {
    /// The document that was matched.
    pub document: SearchDocument,
    /// Score as evaluated by the search engine.
    pub score: f32,
    /// Explanation of the score if enabled,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Value>,
    /// Additional metadata, if enabled
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "$metadata")]
    pub metadata: Option<Value>,
}

/// The payload returned describing how many results matched and the matching documents (within offset and limit requested).
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, ToSchema)]
pub struct SearchResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchHit>,
}

/// This payload returns the total number of docs and the last updated doc.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema, Default)]
pub struct StatusResult {
    /// Total number of all documents
    pub total: Option<u64>,
    /// Id of last updated doc
    pub last_updated_vex_id: Option<String>,
    /// Name of last updated doc
    pub last_updated_vex_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}
