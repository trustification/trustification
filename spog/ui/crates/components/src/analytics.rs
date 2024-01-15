#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchContext {
    Advisory,
    Cve,
    Sbom,
    Package,
}
