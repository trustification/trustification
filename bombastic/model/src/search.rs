use serde_json::Value;
use sikula::prelude::*;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Packages<'a> {
    #[search(default)]
    Package(Primary<'a>),
    #[search]
    Type(Primary<'a>),
    #[search]
    Namespace(Primary<'a>),
    #[search(default)]
    Version(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    #[search]
    Created(Ordered<time::OffsetDateTime>),
    #[search]
    Digest(Primary<'a>),
    #[search]
    License(Primary<'a>),
    #[search(scope)]
    Supplier(Primary<'a>),
    #[search]
    Qualifier(Qualified<'a, &'a str>),
    #[search]
    Dependency(Primary<'a>),
    Application,
    Library,
    Framework,
    Container,
    OperatingSystem,
    Device,
    Firmware,
    File,
}

/// A document returned from the search index for every match.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchDocument {
    /// SBOM identifier
    pub id: String,
    /// SBOM package name
    pub name: String,
    /// SBOM package version
    pub version: String,
    /// SBOM product identifier
    pub cpe: String,
    /// SBOM package URL
    pub purl: String,
    /// SBOM SHA256 digest
    pub sha256: String,
    /// SBOM license
    pub license: String,
    /// SBOM supplier
    pub supplier: String,
    /// SBOM classifier
    pub classifier: String,
    /// SBOM description
    pub description: String,
    /// Snippet highlighting part of description that matched
    pub snippet: String,
    /// SBOM creation time in RFC3339 format
    #[schema(value_type = String)]
    pub created: time::OffsetDateTime,
    /// List of dependency package names that matched
    pub dependencies: Vec<String>,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchHit {
    /// The document that was matched.
    pub document: SearchDocument,
    /// Score as evaluated by the search engine.
    pub score: f32,
    /// Explanation of the score if enabled,
    pub explanation: Option<Value>,
}

/// The payload returned describing how many results matched and the matching documents (within offset and limit requested).
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchHit>,
}
