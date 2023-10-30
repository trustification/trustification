use super::pkg::PackageRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::{Deref, DerefMut};
use time::OffsetDateTime;
use utoipa::openapi::{KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, SchemaType};
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Vulnerability {
    cve: "cve-2023-0286".to_string(),
    summary: "There is a type confusion vulnerability...".to_string(),
    severity: Some("Important".to_string()),
    advisory: "https://access.redhat.com/security/cve/cve-2023-0286".to_string(),
    date: None,
    cvss3: Some(Cvss3 {
        score: "7.4".to_string(),
        status: "verified".to_string(),
    }),
    packages: vec![PackageRef {
        purl: "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string(),
    }
]
}))]
pub struct Vulnerability {
    pub cve: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss3: Option<Cvss3>,
    pub summary: String,
    pub advisory: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<PackageRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
#[schema(example = json!(Cvss3{
    score: "7.3".to_string(),
    status: "verified".to_string()
}))]
pub struct Cvss3 {
    pub score: String,
    pub status: String,
}

/// Report of vulnerabilities of an SBOM.
#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SbomReport {
    /// The SBOM name
    pub name: String,
    /// The SBOM version
    pub version: Option<String>,
    /// The time the document was created
    pub created: Option<OffsetDateTime>,

    /// Vulnerabilities summary
    pub summary: Vec<SummaryEntry>,
    /// Vulnerabilities list
    pub details: Vec<SbomReportVulnerability>,
    /// Traces from the vulnerable PURL back to the SBOM root
    #[schema(schema_with=schema::backtraces)]
    pub backtraces: BTreeMap<String, BTreeSet<Backtrace>>,
}

/// Entry in the [`SbomReport`] summary.
#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SummaryEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(inline, schema_with=schema::severity)]
    pub severity: Option<cvss::Severity>,
    pub count: usize,
}

mod schema {
    use crate::vuln::Backtrace;
    use cvss::Severity;
    use utoipa::openapi::schema::AdditionalProperties;
    use utoipa::openapi::*;
    use utoipa::ToSchema;

    pub fn backtraces() -> Object {
        let backtrace = Backtrace::schema().1;
        let backtraces = ArrayBuilder::new().unique_items(true).items(backtrace).build();

        ObjectBuilder::new()
            .schema_type(SchemaType::Object)
            .description(Some("Traces from the vulnerable PURL back to the SBOM root"))
            .additional_properties(Some(AdditionalProperties::RefOr(backtraces.into())))
            .build()
    }

    pub fn severity() -> Object {
        ObjectBuilder::new()
            .schema_type(SchemaType::String)
            .enum_values(Some(
                [
                    Severity::None,
                    Severity::Low,
                    Severity::Medium,
                    Severity::High,
                    Severity::Critical,
                ]
                .into_iter()
                .map(|s| s.as_str()),
            ))
            .build()
    }
}

/// A trace from a vulnerability back to its top-most component.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Backtrace(pub Vec<String>);

impl<'__s> ToSchema<'__s> for Backtrace {
    fn schema() -> (&'__s str, RefOr<Schema>) {
        let schema = ObjectBuilder::new()
            .schema_type(SchemaType::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uri)))
            .description(Some("A Package URL"))
            .to_array_builder()
            .unique_items(true)
            .build();

        ("Backtrace", schema.into())
    }
}

impl Deref for Backtrace {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Backtrace {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SbomReportVulnerability {
    /// The ID of the vulnerability
    pub id: String,
    /// A plain text description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Timestamp the vulnerability was initially published
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<OffsetDateTime>,
    /// Timestamp the vulnerability was last updated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<OffsetDateTime>,
    /// A map listing the packages affected by this vulnerability, and the available remediations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub affected_packages: BTreeMap<String, Vec<Remediation>>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sources: HashMap<Source, SourceDetails>,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, serde::Serialize, serde::Deserialize)]
pub struct Remediation {
    /// Detail information on the remediation.
    pub details: String,
}

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, serde::Serialize, serde::Deserialize, Hash)]
pub enum Source {
    Mitre,
}

#[derive(Clone, Debug, PartialEq, ToSchema, Serialize, Deserialize)]
pub struct SourceDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}
