#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub id: String,
    pub name: String,
    pub version: String,
    pub cpe: String,
    pub purl: String,
    pub sha256: String,
    pub license: String,
    pub supplier: String,
    pub classifier: String,
    pub description: String,
    pub snippet: String,
    pub created: time::OffsetDateTime,
    pub dependencies: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchResult {
    pub total: usize,
    pub result: Vec<SearchDocument>,
}
