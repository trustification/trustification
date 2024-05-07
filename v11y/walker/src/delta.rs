use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub type DeltaLog = Vec<Delta>;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Delta {
    #[serde(with = "time::serde::rfc3339")]
    pub fetch_time: OffsetDateTime,
    pub number_of_changes: usize,
    pub new: Vec<CveInfo>,
    pub updated: Vec<CveInfo>,
    pub error: Vec<CveInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CveInfo {
    pub cve_id: String,
    pub cve_org_link: url::Url,
    pub github_link: url::Url,
}
