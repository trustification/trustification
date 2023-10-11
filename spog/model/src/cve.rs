use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CveDetails {
    pub id: String,
    pub products: BTreeMap<ProductCveStatus, Vec<ProductRelatedToCve>>,
    pub advisories: Vec<AdvisoryOverview>,

    #[serde(default)]
    pub details: Vec<v11y_model::Vulnerability>,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum ProductCveStatus {
    Fixed,
    FirstFixed,
    FirstAffected,
    KnownAffected,
    LastAffected,
    KnownNotAffected,
    Recommended,
    UnderInvestigation,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProductRelatedToCve {
    pub sbom_id: String,
    pub packages: Vec<PackageRelatedToProductCve>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PackageRelatedToProductCve {
    pub purl: String,
    pub r#type: String,
}


#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AdvisoryOverview {
    pub id: String,
    pub title: String,
}
