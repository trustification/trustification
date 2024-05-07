use serde_json::Value;
use sikula::prelude::*;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum PackageInfo<'a> {
    /// Search by Package URL
    #[search(default)]
    Purl(Primary<'a>),
    ///
    /// Example queries:
    ///
    /// ```ignore
    /// type:oci
    /// ```
    Type(&'a str),
    #[search(default)]
    Version(Primary<'a>),
    #[search(scope)]
    Name(Primary<'a>),
    #[search(scope)]
    Namespace(Primary<'a>),
    #[search(sort)]
    Created(Ordered<time::OffsetDateTime>),
    #[search(scope)]
    Supplier(Primary<'a>),
    #[search(scope)]
    License(&'a str),
    #[search(default)]
    Description(&'a str),
    Qualifier(Qualified<'a, &'a str>),
}

/// A document returned from the search index for every match.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchPackageDocument {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// package package URL
    pub purl: String,
    /// package SHA256 digest
    pub sha256: String,
    /// package license
    pub license: String,
    /// package supplier
    pub supplier: String,
    /// package classifier
    pub classifier: String,
    /// package description
    pub description: String,
    pub purl_type: String,
    pub purl_name: String,
    pub purl_namespace: String,
    pub purl_version: String,
    pub purl_qualifiers: String,
    pub purl_qualifiers_values: String,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchPackageHit {
    /// The document that was matched.
    pub document: SearchPackageDocument,
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
pub struct SearchPackageResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchPackageHit>,
}
