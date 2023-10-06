use std::fs::File;
use std::path::{Path, PathBuf};

use derive_more::{Display, Error};
use serde_json::Error;
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};
use tokio::fs::create_dir_all;

use v11y_model::Vulnerability;

#[derive(Debug, Display, Error)]
pub enum DbError {
    #[display(fmt = "I/O error: {}", "_0")]
    Io(std::io::Error),

    #[display(fmt = "Serialization error: {}", "_0")]
    Serialization(serde_json::Error),
}

impl From<std::io::Error> for DbError {
    fn from(inner: std::io::Error) -> Self {
        Self::Io(inner)
    }
}

impl From<serde_json::Error> for DbError {
    fn from(inner: Error) -> Self {
        Self::Serialization(inner)
    }
}

pub struct Db {
    data_dir: PathBuf,
}

#[allow(unused)]
impl Db {
    pub async fn new(base: impl AsRef<Path>) -> Result<Self, DbError> {
        let db = Self {
            data_dir: base.as_ref().to_owned(),
        };
        db.initialize().await?;
        Ok(db)
    }

    async fn initialize(&self) -> Result<(), DbError> {
        self.ensure_data_directory().await?;
        Ok(())
    }

    async fn ensure_data_directory(&self) -> Result<(), DbError> {
        if !self.data_dir.exists() {
            create_dir_all(&self.data_dir).await?;
        }

        Ok(())
    }

    async fn ensure_origin_directory(&self, origin: &str) -> Result<PathBuf, DbError> {
        let origin_dir = self.data_dir.join(origin);
        if !origin_dir.exists() {
            create_dir_all(&origin_dir).await?
        }

        Ok(origin_dir)
    }

    async fn ensure_hash_directory(&self, base: &Path, id: &str) -> Result<PathBuf, DbError> {
        let hash_dir = base.join(Self::hash_prefix_of(&id.to_lowercase()));

        if !hash_dir.exists() {
            create_dir_all(&hash_dir).await?;
        }

        Ok(hash_dir)
    }

    fn get_hash_directories(&self, id: &str, origin: Option<String>) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        let hash_prefix = Self::hash_prefix_of(id);
        match origin {
            None => {
                for origin in self.get_known_origins() {
                    let dir = self.data_dir.join(origin).join(&hash_prefix);
                    if dir.exists() {
                        dirs.push(dir)
                    }
                }
            }
            Some(origin) => {
                let dir = self.data_dir.join(origin).join(hash_prefix);
                if dir.exists() {
                    dirs.push(dir)
                }
            }
        }

        dirs
    }

    fn hash_prefix_of(id: &str) -> String {
        let mut hasher = Sha1::default();
        hasher.update(id.to_lowercase());
        let output = hasher.finalize_fixed();
        format!("{:x}{:x}{:x}{:x}", output[0], output[1], output[2], output[3])
    }

    pub async fn ingest(&self, vuln: &Vulnerability) -> Result<(), DbError> {
        let dir = self.ensure_origin_directory(&vuln.origin).await?;
        let hash_dir = self.ensure_hash_directory(&dir, &vuln.id).await?;

        let vuln_file = hash_dir.join(format!("{}.json", vuln.id.to_lowercase()));

        // todo: write to a tempfile and then rename it.
        let file = File::create(vuln_file)?;
        let json = serde_json::to_writer_pretty(file, vuln);
        Ok(())
    }

    pub async fn get(&self, id: &str, origin: Option<String>) -> Result<Vec<Vulnerability>, DbError> {
        let mut vulnerabilities = Vec::new();

        for dir in self.get_hash_directories(id, origin) {
            let file = dir.join(format!("{}.json", id.to_lowercase()));
            if file.exists() {
                if let Ok(reader) = File::open(file.clone()) {
                    let result = serde_json::from_reader(reader);

                    match result {
                        Ok(vuln) => vulnerabilities.push(vuln),
                        Err(e) => {
                            log::error!("Error reading {}", file.to_str().unwrap_or(""));
                        }
                    }
                } else {
                    log::error!("Error opening {}", file.to_str().unwrap_or(""));
                }
            }
        }

        Ok(vulnerabilities)
    }

    #[allow(unused)]
    pub fn get_known_origins(&self) -> Vec<String> {
        let mut origins = Vec::new();
        if let Ok(dir) = self.data_dir.read_dir() {
            for entry in dir.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    origins.push(name.to_string())
                }
            }
        }

        origins
    }
}

#[cfg(test)]
mod test {
    use tempdir::TempDir;

    use v11y_model::{Reference, ScoreType, Severity, Vulnerability};

    use crate::db::Db;

    async fn create_db() -> Result<Db, anyhow::Error> {
        let dir = TempDir::new("v11y")?;
        let db = Db::new(dir).await?;
        // not failing is success
        Ok(db)
    }

    #[tokio::test]
    async fn ingest_minimal() -> Result<(), anyhow::Error> {
        let db = create_db().await?;

        let vuln1 = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: Default::default(),
            severities: Default::default(),
            affected: vec![],
            related: Default::default(),
            references: Default::default(),
        };

        db.ingest(&vuln1).await?;

        let vuln2 = Vulnerability {
            origin: "snyk".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: Default::default(),
            severities: Default::default(),
            affected: vec![],
            related: Default::default(),
            references: Default::default(),
        };

        db.ingest(&vuln2).await?;

        let vuln3 = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-345".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: Default::default(),
            severities: Default::default(),
            affected: vec![],
            related: Default::default(),
            references: Default::default(),
        };

        db.ingest(&vuln3).await?;

        let result = db.get("CVE-123", Some("osv".into())).await?;
        assert_eq!(1, result.len());
        assert_eq!(vuln1, result[0]);

        let result = db.get("CVE-123", Some("snyk".into())).await?;
        assert_eq!(1, result.len());
        assert_eq!(vuln2, result[0]);

        let result = db.get("CVE-345", Some("osv".into())).await?;
        assert_eq!(1, result.len());
        assert_eq!(vuln3, result[0]);

        let result = db.get("CVE-123", None).await?;
        assert_eq!(2, result.len());
        assert!(result.contains(&vuln1));
        assert!(result.contains(&vuln2));

        Ok(())
    }

    #[tokio::test]
    async fn ingest_maximal() -> Result<(), anyhow::Error> {
        let db = create_db().await?;

        let osv_vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec!["GHSA-foo-ghz".to_string()],
            severities: vec![Severity {
                r#type: ScoreType::Cvss3,
                source: "CVE".to_string(),
                score: 6.8,
                additional: Some("n:4/v:2".to_string()),
            }],
            affected: vec![],
            related: vec!["CVE-8675".to_string()],
            references: vec![Reference {
                r#type: "ADVISORY".to_string(),
                url: "http://osv.dev/foo".to_string(),
            }],
        };

        db.ingest(&osv_vuln).await?;

        let result = db.get("CVE-123", Some("osv".to_string())).await?;
        assert_eq!(1, result.len());
        assert_eq!(result[0], osv_vuln);

        let snyk_vuln = Vulnerability {
            origin: "snyk".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec!["GHSA-foo-ghz".to_string()],
            severities: vec![Severity {
                r#type: ScoreType::Cvss3,
                source: "CVE".to_string(),
                score: 7.8,
                additional: Some("n:1/v:2".to_string()),
            }],
            affected: vec![],
            related: vec!["CVE-8675".to_string(), "CVE-42".to_string()],
            references: vec![Reference {
                r#type: "WEB".to_string(),
                url: "http://snyk.com/foo".to_string(),
            }],
        };

        db.ingest(&snyk_vuln).await?;
        let result = db.get("CVE-123", Some("snyk".to_string())).await?;
        assert_eq!(1, result.len());
        assert_eq!(result[0], snyk_vuln);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_updated_overwrite() -> Result<(), anyhow::Error> {
        let db = create_db().await?;

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec!["GHSA-foo-ghz".to_string()],
            severities: vec![Severity {
                r#type: ScoreType::Cvss3,
                source: "CVE".to_string(),
                score: 6.8,
                additional: Some("n:4/v:2".to_string()),
            }],
            affected: vec![],
            related: vec![],
            references: Default::default(),
        };

        db.ingest(&vuln).await?;

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec!["GHSA-foo-ghz".to_string()],
            severities: vec![
                Severity {
                    r#type: ScoreType::Cvss3,
                    score: 9.8,
                    source: "CVE".to_string(),
                    additional: Some("n:4/v:2".to_string()),
                },
                Severity {
                    r#type: ScoreType::Cvss4,
                    score: 7.3,
                    source: "CVE".to_string(),
                    additional: None,
                },
            ],
            affected: vec![],
            related: vec!["CVE-8675".to_string(), "CVE-42".to_string()],
            references: Default::default(),
        };

        db.ingest(&vuln).await?;

        let result = db.get("CVE-123", Some("osv".into())).await?;
        assert_eq!(1, result.len());
        assert_eq!(vuln, result[0]);

        Ok(())
    }
}
