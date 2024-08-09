use serde_json::Value;
use sikula::prelude::*;
use std::fmt::Debug;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Cves<'a> {
    /// Search by CVE id
    #[search(default)]
    Id(Primary<'a>),

    #[search(default)]
    Title(Primary<'a>),

    #[search(default)]
    Description(Primary<'a>),

    #[search(sort)]
    Score(PartialOrdered<f64>),

    DateReserved(Ordered<OffsetDateTime>),
    #[search(sort)]
    DatePublished(Ordered<OffsetDateTime>),
    #[search(sort)]
    DateUpdated(Ordered<OffsetDateTime>),
    #[search(sort)]
    DateRejected(Ordered<OffsetDateTime>),
    #[search(sort)]
    IndexedTimestamp(Ordered<time::OffsetDateTime>),

    Severity(&'a str),
    Low,
    Medium,
    High,
    Critical,

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
    pub indexed_timestamp: OffsetDateTime,
    pub cvss3x_score: Option<f64>,

    #[serde(with = "time::serde::rfc3339::option")]
    pub date_published: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub date_updated: Option<OffsetDateTime>,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(Clone, serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
#[aliases(SearchHitWithDocument = SearchHit<SearchDocument>)]
pub struct SearchHit<T> {
    /// The document that was matched.
    pub document: T,
    /// Score as evaluated by the search engine.
    pub score: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Explanation of the score if enabled,
    pub explanation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "$metadata")]
    /// Additional metadata, if enabled
    pub metadata: Option<Value>,
}

impl<T> SearchHit<T> {
    pub fn map<U, F>(self, f: F) -> SearchHit<U>
    where
        F: FnOnce(T) -> U,
    {
        let Self {
            document,
            score,
            explanation,
            metadata,
        } = self;
        SearchHit {
            document: f(document),
            score,
            explanation,
            metadata,
        }
    }
}

/// This payload returns the total number of docs and the last updated doc.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema, Default)]
pub struct StatusResult {
    /// Total number of all documents
    pub total: Option<u64>,
    /// Id of last updated doc
    pub last_updated_cve_id: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}
