use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!(PackageInfo {
    purl: "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string(),
    vulnerabilities: vec![V11yRef {
        cve: "cve-2023-0286".into(),
        severity: "low".to_string()
    }],
}))]
pub struct PackageInfo {
    pub purl: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<V11yRef>,
}

impl PackageInfo {
    pub fn get_v11y_severity_count(&self, level: String) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v11y_model| v11y_model.severity == level)
            .count()
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(V11yRef {
    cve: "cve-2023-0286".into(),
    severity: "low".to_string()
}))]
pub struct V11yRef {
    pub cve: String,
    pub severity: String,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct PackageProductDetails {
    pub related_products: Vec<ProductRelatedToPackage>,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ProductRelatedToPackage {
    pub sbom_uid: String,
    pub backtraces: Vec<Vec<PackageUrl<'static>>>,
}
