use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct UserPreferences {
    pub user_id: String,
    pub preferences: Option<Preferences>,
}

impl Default for UserPreferences {
    fn default() -> Self {
        UserPreferences {
            user_id: "".to_string(),
            preferences: Some(Preferences {
                sbom1: None,
                sbom2: None,
                sbom3: None,
                sbom4: None,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Preferences {
    pub sbom1: Option<String>,
    pub sbom2: Option<String>,
    pub sbom3: Option<String>,
    pub sbom4: Option<String>,
}

#[derive(Clone, serde::Deserialize, ToSchema, serde::Serialize)]
pub struct DashboardStatus {
    pub sbom_summary: SbomStatus,
    pub csaf_summary: CSAFStatus,
    pub cve_summary: CveStatus,
}

#[derive(Clone, serde::Deserialize, ToSchema, serde::Serialize)]
pub struct SbomStatus {
    /// Total number of all documents
    pub total_sboms: Option<u64>,
    /// Id of last updated doc
    pub last_updated_sbom_id: Option<String>,
    /// name of last updated doc
    pub last_updated_sbom_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}

#[derive(Clone, serde::Deserialize, ToSchema, serde::Serialize)]
pub struct CSAFStatus {
    /// Total number of all documents
    pub total_csafs: Option<u64>,
    /// Id of last updated doc
    pub last_updated_csaf_id: Option<String>,
    /// name of last updated doc
    pub last_updated_csaf_name: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}

#[derive(Clone, serde::Deserialize, ToSchema, serde::Serialize)]
pub struct CveStatus {
    /// Total number of all documents
    pub total_cves: Option<u64>,
    /// Name of last updated doc
    pub last_updated_cve: Option<String>,
    /// Updated time of last updated doc
    pub last_updated_date: Option<OffsetDateTime>,
}

// Last 10 SBOMs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Last10SbomVulnerabilitySummaryVulnerabilities {
    pub none: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Last10SbomVulnerabilitySummary {
    pub sbom_id: String,
    pub sbom_name: String,
    pub vulnerabilities: Last10SbomVulnerabilitySummaryVulnerabilities,
}
