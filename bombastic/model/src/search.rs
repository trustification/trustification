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
    /// Snippet highlighting part of description that matched.
    pub snippet: String,
    /// SBOM creation time in RFC3339 format.
    #[schema(value_type = String)]
    pub created: time::OffsetDateTime,
    /// List of dependency package names that matched.
    pub dependencies: Vec<String>,
}

/// The payload returned describing how many results matched and the matching documents (within offset and limit requested).
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct SearchResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchDocument>,
}
