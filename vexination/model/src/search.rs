#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub advisory: String,
    pub cve: String,
    pub title: String,
    pub release: time::OffsetDateTime,
    pub description: String,
    pub cvss: f64,
    pub affected: Vec<String>,
    pub fixed: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchResult {
    pub total: usize,
    pub result: Vec<SearchDocument>,
}
