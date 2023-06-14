#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub advisory_id: String,
    pub advisory_title: String,
    pub advisory_date: time::OffsetDateTime,
    pub advisory_snippet: String,
    pub advisory_desc: String,

    pub cve_id: String,
    pub cve_title: String,
    pub cve_release: time::OffsetDateTime,
    pub cve_snippet: String,
    pub cve_desc: String,
    pub cve_cvss: Option<f64>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchResult {
    pub total: usize,
    pub result: Vec<SearchDocument>,
}
