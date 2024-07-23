use serde_json::Value;
use sikula::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Packages<'a> {
    /// Search by SBOM id (the storage ID)
    #[search(default)]
    Id(&'a str),
    /// Search by SBOM uid (the actual ID)
    Uid(&'a str),
    /// Search package name and package reference.
    ///
    /// Example queries:
    ///
    /// ```ignore
    /// package:openssl
    /// ubi in:package
    /// ```
    #[search(default)]
    Package(Primary<'a>),
    /// Search package types based on Package URL types.
    ///
    /// Example queries:
    ///
    /// ```ignore
    /// type:oci
    /// ```
    Type(&'a str),
    #[search]
    Namespace(&'a str),
    #[search(default)]
    Version(Primary<'a>),
    #[search(default)]
    Description(&'a str),
    #[search(sort)]
    Created(Ordered<time::OffsetDateTime>),
    #[search(sort)]
    IndexedTimestamp(Ordered<time::OffsetDateTime>),
    Digest(&'a str),
    #[search(scope)]
    License(&'a str),
    #[search(scope)]
    Supplier(Primary<'a>),
    Qualifier(Qualified<'a, &'a str>),
    #[search(scope)]
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
    /// SBOM (storage) identifier
    pub id: String,
    /// SBOM unique identifier
    pub uid: Option<String>,
    /// The creation time of the document.
    #[schema(value_type = String)]
    pub indexed_timestamp: time::OffsetDateTime,
    /// SBOM package name
    pub name: String,
    /// SBOM package version
    pub version: String,
    /// SBOM product identifier
    pub cpe: Option<String>,
    /// SBOM package URL
    pub purl: Option<String>,
    /// SHA256 of the full file, as stored
    pub file_sha256: String,
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
    /// Number of dependencies with package names that matched
    pub dependencies: u64,
}

/// The hit describes the document, its score and optionally an explanation of why that score was given.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
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

/// This payload returns the total number of docs and the last updated doc.
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema, Default)]
pub struct StatusResult {
    /// Total number of all documents
    pub total: Option<u64>,
    /// id of last updated doc
    pub last_updated_sbom_id: Option<String>,
    /// name of last updated doc
    pub last_updated_sbom_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}

// impl Default for StatusResult {
//     fn default() -> Self {
//         StatusResult {
//             total: 0,
//             last_updated_sbom: "".to_string(),
//             last_updated_date: OffsetDateTime::now_utc(),
//         }
//     }
// }
