use serde_json::Value;
use sikula::prelude::*;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Cves<'a> {
    /// Search by CVE id
    #[search(default, sort)]
    Id(&'a str),

    #[search(default)]
    Title(Primary<'a>),

    #[search(default)]
    Description(Primary<'a>),

    Published,
    Rejected,
}

/// A document returned from the search index for every match.
#[derive(Clone, serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchDocument {
    /// CVE identifier
    pub id: String,
    pub published: bool,
    pub title: Option<String>,
    pub descriptions: Vec<String>,

    pub cvss31_score: Option<f64>,
    pub cvss30_score: Option<f64>,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(Clone, serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchHit {
    /// The document that was matched.
    pub document: SearchDocument,
    /// Score as evaluated by the search engine.
    pub score: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Explanation of the score if enabled,
    pub explanation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "$metadata")]
    /// Additional metadata, if enabled
    pub metadata: Option<Value>,
}

/// The payload returned describing how many results matched and the matching documents (within offset and limit requested).
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchHit>,
}
