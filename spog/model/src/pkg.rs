use std::ops::Deref;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Package {
    purl: Some("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string()), href: Some(format!("/api/package?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))),
    sbom: Some(format!("/api/package/sbom?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6"))),
    vulnerabilities: vec![VulnerabilityRef {
        cve: "cve-2023-0286".into(),
        href: "https://access.redhat.com/security/cve/cve-2023-0286".into()
    }],
    snyk: None,
}))]
pub struct Package {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snyk: Option<SnykData>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(VulnerabilityRef {
    cve: "cve-2023-0286".into(),
    href: "https://access.redhat.com/security/cve/cve-2023-0286".into()
}))]
pub struct VulnerabilityRef {
    pub cve: String,
    pub href: String,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(PackageRef {
    purl: "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string(),
    href: format!("/api/package?purl={}", &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6")),
    sbom: None
}))]
pub struct PackageRef {
    pub purl: String,
    pub href: String,
    pub sbom: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct SnykData;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(vec![
    PackageRef {
        purl: "pkg:maven/io.vertx/vertx-web-common@4.3.7".to_string(),
        href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/io.vertx/vertx-web-common@4.3.7")),
        sbom: None,
    }
]))]
pub struct PackageDependencies(pub Vec<PackageRef>);

impl Deref for PackageDependencies {
    type Target = [PackageRef];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(vec![
    PackageRef {
        purl: "pkg:maven/io.quarkus/quarkus-vertx-http@2.16.2.Final".to_string(),
        href: format!("/api/package?purl={}", &urlencoding::encode("pkg:maven/io.quarkus/quarkus-vertx-http@2.16.2.Final")),
        sbom: None,
    }
]))]
pub struct PackageDependents(pub Vec<PackageRef>);

impl Deref for PackageDependents {
    type Target = [PackageRef];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = "[\"pkg:maven/io.vertx/vertx-web@4.3.7\"]")]
pub struct PackageList(pub Vec<String>);

impl PackageList {
    pub fn list(&self) -> &Vec<String> {
        &self.0
    }
}
