#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq)]
pub struct SearchDocument {
    pub advisory: String,
    pub cve: String,
    pub title: String,
    pub release: time::OffsetDateTime,
    pub description: String,
    pub cvss: f64,
    pub affected: Vec<ProductPackage>,
    pub fixed: Vec<ProductPackage>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct ProductPackage {
    cpe: Option<String>,
    purl: Option<String>,
}
