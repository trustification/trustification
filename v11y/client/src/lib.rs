use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
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
    pub severities: Vec<Severity>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub ranges: Vec<Range>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub related: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub references: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Severity {
    pub r#type: ScoreType,
    pub score: f32,
    pub additional: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Range {
    pub lower: Option<Version>,
    pub upper: Option<Version>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Version {
    Inclusive(String),
    Exclusive(String),
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
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

impl ScoreType {
    pub fn to_string(&self) -> String {
        match self {
            ScoreType::Cvss3 => "cvss3".to_string(),
            ScoreType::Cvss4 => "cvss4".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    pub r#type: EventType,
    pub event: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EventType {
    Introduced,
    Fixed,
}

#[allow(unused)]
pub struct V11yClient {
    url: String,
}

impl V11yClient {
    pub fn new(url: &str) -> Self {
        Self { url: url.to_owned() }
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
