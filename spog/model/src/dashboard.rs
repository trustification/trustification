#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct DashboardStatus {
    pub sbom_summary: SbomStatus,
    pub csaf_summary: CSAFStatus,
    pub cve_summary: CveStatus,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SbomStatus {
    /// Total number of all documents
    pub total_sboms: Option<u64>,
    /// Id of last updated doc
    pub last_updated_sbom_id: Option<String>,
    /// name of last updated doc
    pub last_updated_sbom_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CSAFStatus {
    /// Total number of all documents
    pub total_csafs: Option<u64>,
    /// Id of last updated doc
    pub last_updated_csaf_id: Option<String>,
    /// name of last updated doc
    pub last_updated_csaf_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<String>,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CveStatus {
    /// Total number of all documents
    pub total_cves: Option<u64>,
    /// Name of last updated doc
    pub last_updated_cve: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<String>,
}
