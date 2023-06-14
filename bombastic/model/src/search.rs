#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub sbom_id: String,
    pub dependent: String,
    pub name: String,
    pub purl: String,
    pub sha256: String,
    pub license: String,
    pub supplier: String,
    pub classifier: String,
    pub description: String,
    pub created: time::OffsetDateTime,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchResult {
    pub total: usize,
    pub result: Vec<SearchDocument>,
}
