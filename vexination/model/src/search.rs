use utoipa::ToSchema;

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
    /// List of CVE identifiers that matched within the advisory
    pub cves: Vec<String>,
    /// Highest CVSS score in vulnerabilities matched within the advisory
    pub cvss_max: Option<f64>,
}

/// The payload returned describing how many results matched and the matching documents (within offset and limit requested).
#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, ToSchema)]
pub struct SearchResult {
    /// Total number of matching documents
    pub total: usize,
    /// Documents matched up to max requested
    pub result: Vec<SearchDocument>,
}
