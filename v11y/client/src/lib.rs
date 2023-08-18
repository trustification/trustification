use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Vulnerability {
    pub origin: String,
    pub id: String,
    pub modified: DateTime<Utc>,
    pub published: DateTime<Utc>,
    pub withdrawn: Option<DateTime<Utc>>,
    pub summary: String,
    pub details: String,
    #[serde(skip_serializing_if = "HashSet::is_empty", default = "HashSet::default")]
    pub aliases: HashSet<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub affected: Vec<Affected>,
    #[serde(skip_serializing_if = "HashSet::is_empty", default = "HashSet::default")]
    pub severities: HashSet<Severity>,
    #[serde(skip_serializing_if = "HashSet::is_empty", default = "HashSet::default")]
    pub related: HashSet<String>,
    #[serde(skip_serializing_if = "HashSet::is_empty", default = "HashSet::default")]
    pub references: HashSet<Reference>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Affected {
    pub package: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub ranges: Vec<Range>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Severity {
    pub r#type: ScoreType,
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Range {
    pub lower: Option<Version>,
    pub upper: Option<Version>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Version {
    Inclusive(String),
    Exclusive(String),
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash)]
pub enum ScoreType {
    Cvss3,
    Cvss4,
    Unknown,
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

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
    pub r#type: String,
    pub url: String,
}

pub struct V11yUrl {
    base_url: Url,
}

impl V11yUrl {
    pub fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    pub fn vulnerability_url(&self) -> Url {
        Url::parse(&format!("{}/api/v1/vulnerability", self.base_url)).unwrap()
    }
}

#[allow(unused)]
pub struct V11yClient {
    v11y_url: V11yUrl,
}

impl V11yClient {
    pub fn new(url: Url) -> Self {
        Self {
            v11y_url: V11yUrl::new(url),
        }
    }

    pub async fn ingest_vulnerability(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        Ok(reqwest::Client::new()
            .post(self.v11y_url.vulnerability_url())
            .json(&vuln)
            .send()
            .await?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod test {
    use crate::Vulnerability;

    #[tokio::test]
    async fn serialization() -> Result<(), anyhow::Error> {
        let json = r#"
            {
                "origin": "osv",
                "id": "CVE-123",
                "modified": "2023-08-08T18:17:02Z",
                "published": "2023-08-08T18:17:02Z",
                "summary": "This is my summary",
                "details": "And\nhere are some\ndetails",
                "related": [
                    "related-foo",
                    "related-bar"
                ]
            }
        "#;

        let vuln: Vulnerability = serde_json::from_str(json)?;

        assert_eq!("osv", vuln.origin);
        assert_eq!("CVE-123", vuln.id);

        Ok(())
    }
}
