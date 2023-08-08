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
    r#type: ScoreType,
    score: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Range {
    lower: Option<Version>,
    upper: Option<Version>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Version {
    Inclusive(String),
    Exclusive(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ScoreType {
    Cvss3,
    Cvss4,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Event {
    r#type: EventType,
    event: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EventType {
    Introduced,
    Fixed,
}

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
