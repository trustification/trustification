use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct Vulnerability {
    pub origin: String,
    pub id: String,
    pub modified: DateTime<Utc>,
    pub published: DateTime<Utc>,
    pub withdrawn: Option<DateTime<Utc>>,
    pub summary: String,
    pub details: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub affected: Vec<Affected>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub severities: Vec<Severity>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub related: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub references: Vec<Reference>,
}

impl PartialEq for Vulnerability {
    fn eq(&self, other: &Self) -> bool {
        self.origin.eq(&other.origin)
            && self.id.eq(&other.id)
            && self.modified.eq(&other.modified)
            && self.published.eq(&other.published)
            && self.withdrawn.eq(&other.withdrawn)
            && self.details.eq(&other.details)
            && self
                .aliases
                .iter()
                .collect::<HashSet<_>>()
                .eq(&other.aliases.iter().collect::<HashSet<_>>())
            && self
                .severities
                .iter()
                .collect::<HashSet<_>>()
                .eq(&other.severities.iter().collect::<HashSet<_>>())
            && self
                .related
                .iter()
                .collect::<HashSet<_>>()
                .eq(&other.related.iter().collect::<HashSet<_>>())
            && self
                .references
                .iter()
                .collect::<HashSet<_>>()
                .eq(&other.references.iter().collect::<HashSet<_>>())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, ToSchema)]
pub struct Affected {
    pub package: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub ranges: Vec<Range>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct Severity {
    pub r#type: ScoreType,
    pub source: String,
    pub score: f32,
    pub additional: Option<String>,
}

impl PartialEq<Severity> for Severity {
    fn eq(&self, other: &Self) -> bool {
        self.r#type == other.r#type
    }
}
impl Eq for Severity {}

impl Hash for Severity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.r#type.hash(state)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, ToSchema)]
pub struct Range {
    pub lower: Option<Version>,
    pub upper: Option<Version>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    Inclusive(String),
    Exclusive(String),
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Copy, Clone, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScoreType {
    Cvss2,
    Cvss3,
    Cvss4,
    Unknown,
}

impl ScoreType {
    pub fn from_vector(vector: &Option<String>) -> Self {
        if let Some(vector) = vector {
            if vector.starts_with("CVSS:2") {
                Self::Cvss2
            } else if vector.starts_with("CVSS:3") {
                Self::Cvss3
            } else if vector.starts_with("CVSS:4") {
                Self::Cvss4
            } else {
                Self::Unknown
            }
        } else {
            Self::Unknown
        }
    }
}

impl From<String> for ScoreType {
    fn from(value: String) -> Self {
        if value == "cvss3" {
            Self::Cvss3
        } else if value == "cvss4" {
            Self::Cvss4
        } else {
            Self::Unknown
        }
    }
}

impl Display for ScoreType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScoreType::Cvss2 => {
                write!(f, "cvss2")
            }
            ScoreType::Cvss3 => {
                write!(f, "cvss3")
            }
            ScoreType::Cvss4 => {
                write!(f, "cvss4")
            }
            ScoreType::Unknown => {
                write!(f, "unknown")
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Event {
    pub r#type: EventType,
    pub event: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum EventType {
    Introduced,
    Fixed,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, ToSchema)]
pub struct Reference {
    pub r#type: String,
    pub url: String,
}
