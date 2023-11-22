use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[schema(example = json!(PackageInfo {
    name: Some("redhat:openssl".to_string()),
    namespace: Some("redhat".to_string()),
    version: Some("1.1.1k-7.el8_6".to_string()),
    package_type: Some("rpm".to_string()),
    purl: Some("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string()), href: Some(format!("/api/package?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))),
    sbom: Some(format!("/api/package/sbom?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))),
    supplier: "Organization: Red Hat".to_string().into(),
    vulnerabilities: vec![V11yRef {
        cve: "cve-2023-0286".into(),
        href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
        severity: "low".to_string()
    }],
}))]
pub struct PackageInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<String>,
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
    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
    severity: "low".to_string()
}))]
pub struct V11yRef {
    pub cve: String,
    pub href: String,
    pub severity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct PackageProductDetails {
    pub related_products: Vec<ProductRelatedToPackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, ToSchema)]
pub struct ProductRelatedToPackage {
    pub sbom_uid: String,
    pub dependency_type: String,
}

impl V11yRef {
    pub fn from_string(s: &str) -> V11yRef {
        let json: Value = serde_json::from_str(s).unwrap_or_default();
        let v11y: V11yRef = serde_json::from_value(json).unwrap_or_default();
        v11y
    }
}
