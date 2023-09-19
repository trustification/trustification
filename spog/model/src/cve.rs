use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CveDetails {
    pub id: String,
    pub products: BTreeMap<String, Vec<String>>,
    pub advisories: Vec<AdvisoryOverview>,

    #[serde(default)]
    pub details: Vec<v11y_model::Vulnerability>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AdvisoryOverview {
    pub id: String,
    pub title: String,
}
