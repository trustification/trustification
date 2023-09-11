use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

use chrono::{DateTime, Utc};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use trustification_auth::client::{TokenInjector, TokenProvider};
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

pub struct V11yUrl {
    base_url: Url,
}

impl V11yUrl {
    pub fn new(base_url: Url) -> Self {
        Self { base_url }
    }

    pub fn vulnerability_url(&self) -> Url {
        self.base_url.join("/api/v1/vulnerability").unwrap()
    }

    pub fn get_vulnerability_url(&self, id: impl AsRef<str>) -> Url {
        self.base_url
            .join("/api/v1/vulnerability/")
            .unwrap()
            .join(id.as_ref())
            .unwrap()
    }
}

#[allow(unused)]
pub struct V11yClient {
    client: reqwest::Client,
    v11y_url: V11yUrl,
    provider: Box<dyn TokenProvider>,
}

impl V11yClient {
    pub fn new<P: TokenProvider>(url: Url, provider: P) -> Self
    where
        P: TokenProvider + 'static,
    {
        Self {
            client: reqwest::Client::new(),
            v11y_url: V11yUrl::new(url),
            provider: Box::new(provider),
        }
    }

    pub async fn ingest_vulnerability(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .post(self.v11y_url.vulnerability_url())
            .inject_token(self.provider.as_ref())
            .await?
            .json(&vuln)
            .send()
            .await
            .map(|_| ())?)
    }

    pub async fn get_vulnerability(&self, id: &str) -> Result<Vec<Vulnerability>, anyhow::Error> {
        Ok(self
            .client
            .get(self.v11y_url.get_vulnerability_url(id))
            .inject_token(self.provider.as_ref())
            .await?
            .send()
            .await?
            .error_for_status()?
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
