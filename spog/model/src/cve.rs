use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct CveDetails {
    pub id: String,
    pub products: BTreeMap<String, Vec<String>>,
    pub advisories: Vec<AdvisoryOverview>,

    #[serde(default)]
    pub details: Details,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Details {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AdvisoryOverview {
    pub id: String,
    pub title: String,
}
