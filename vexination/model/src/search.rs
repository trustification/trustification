#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub advisory_id: String,
    pub advisory_title: String,
    pub advisory_date: time::OffsetDateTime,
    pub advisory_snippet: String,
    pub advisory_desc: String,
    pub cvss_max: Option<f64>,
    pub cves: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchResult {
    pub total: usize,
    pub result: Vec<SearchDocument>,
}
