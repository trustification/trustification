use std::collections::BTreeMap;
use std::ops::Deref;
use v11y_model::search::SearchDocument;

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CveDetails {
    pub id: String,
    pub products: BTreeMap<ProductCveStatus, BTreeMap<String, Vec<PackageRelatedToProductCve>>>,
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
    pub sbom_uid: String,
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

#[derive(Clone, serde::Deserialize, serde::Serialize, Debug, PartialEq, utoipa::ToSchema)]
pub struct CveSearchDocument {
    pub document: SearchDocument,

    #[serde(default)]
    pub related_advisories: usize,
    #[serde(default)]
    pub related_products: usize,
}

impl Deref for CveSearchDocument {
    type Target = SearchDocument;

    fn deref(&self) -> &Self::Target {
        &self.document
    }
}
