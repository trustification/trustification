use futures::Stream;
use futures::StreamExt;
use std::str::FromStr;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

use v11y_client::Vulnerability;

static DB_FILE_NAME: &str = "v11y.db";

pub struct Db {
    pool: SqlitePool,
}

#[allow(unused)]
impl Db {
    pub async fn new() -> Result<Self, anyhow::Error> {
        let db = Self {
            pool: SqlitePool::connect_with(if cfg!(test) {
                SqliteConnectOptions::from_str(":memory:")?
            } else {
                SqliteConnectOptions::default()
                    .filename(DB_FILE_NAME)
                    .create_if_missing(true)
            })
            .await?,
        };
        db.initialize().await?;
        Ok(db)
    }

    async fn initialize(&self) -> Result<(), anyhow::Error> {
        self.create_vulnerabilities_table().await?;
        self.create_aliases_table().await?;
        self.create_related_table().await?;
        self.create_severities_table().await?;
        self.create_events_table().await?;
        Ok(())
    }

    async fn create_vulnerabilities_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'vulnerabilities'");
        sqlx::query(
            r#"create table if not exists vulnerabilities (
                    id text not null,
                    origin text not null,
                    modified datetime not null,
                    published datatime not null,
                    withdrawn datetime,
                    summary text,
                    details text
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'vulnerabilities_pk'");
        sqlx::query(
            r#"
            create unique index if not exists vulnerabilities_pk ON vulnerabilities ( id, origin ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_severities_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'severities'");
        sqlx::query(
            r#"create table if not exists severities (
                    vulnerability_id text not null,
                    type text,
                    score text
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'severities_pk'");
        sqlx::query(
            r#"
            create index if not exists severities_pk ON severities ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_aliases_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'aliases'");
        sqlx::query(
            r#"create table if not exists aliases (
                    vulnerability_id text not null,
                    alias text not null
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'aliases_by_id'");
        sqlx::query(
            r#"
            create index if not exists alias_by_id ON aliases ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_related_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'related'");
        sqlx::query(
            r#"create table if not exists related (
                    vulnerability_id text not null,
                    related text not null
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'related_by_id'");
        sqlx::query(
            r#"
            create index if not exists related_by_id ON aliases ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_events_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'events'");
        sqlx::query(
            r#"create table if not exists events (
                    vulnerability_id text not null,
                    event text not null
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'events_by_id'");
        sqlx::query(
            r#"
            create index if not exists events_by_id ON events ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_references_table(&self) -> Result<(), anyhow::Error> {
        log::debug!("create table 'references'");
        sqlx::query(
            r#"create table if not exists references (
                    vulnerability_id text not null,
                    type text not null,
                    url text not null
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'references_by_id'");
        sqlx::query(
            r#"
            create index if not exists references_by_id ON events ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn ingest(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"
                insert or ignore into vulnerabilities (
                    id, origin, modified, published, withdrawn, summary, details
                ) values (
                    $1, $2, $3, $4, $5, $6, $7
                )
            "#,
        )
        .bind(vuln.id.clone())
        .bind(vuln.origin.clone())
        .bind(vuln.modified)
        .bind(vuln.published)
        .bind(vuln.withdrawn)
        .bind(vuln.summary.clone())
        .bind(vuln.details.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[allow(unused)]
    pub async fn get_known_ids(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"select distinct id from vulnerabilities"#)
            .fetch(&self.pool)
            .filter_map(|row| async move {
                if let Ok(row) = row {
                    Some(row.get::<String, _>("id"))
                } else {
                    None
                }
            })
    }

    #[allow(unused)]
    pub async fn get_known_origins(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"select distinct origin from vulnerabilities"#)
            .fetch(&self.pool)
            .filter_map(|row| async move {
                if let Ok(row) = row {
                    Some(row.get::<String, _>("origin"))
                } else {
                    None
                }
            })
    }
}

#[cfg(test)]
mod test {
    use futures::StreamExt;
    use v11y_client::Vulnerability;

    use crate::db::Db;

    #[tokio::test]
    async fn create_db() -> Result<(), anyhow::Error> {
        let _db = Db::new().await?;
        // not failing is success
        Ok(())
    }

    #[tokio::test]
    async fn ingest_minimal() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec![],
            severities: vec![],
            ranges: vec![],
            related: vec![],
            references: vec![],
        };

        db.ingest(&vuln).await?;

        let vuln = Vulnerability {
            origin: "snyk".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec![],
            severities: vec![],
            ranges: vec![],
            related: vec![],
            references: vec![],
        };

        db.ingest(&vuln).await?;

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-345".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: vec![],
            severities: vec![],
            ranges: vec![],
            related: vec![],
            references: vec![],
        };

        db.ingest(&vuln).await?;

        let ids: Vec<_> = db.get_known_ids().await.collect().await;

        println!("{:?}", ids);

        assert_eq!(2, ids.len());
        assert!(ids.contains(&"CVE-123".to_owned()));
        assert!(ids.contains(&"CVE-345".to_owned()));

        let origins: Vec<_> = db.get_known_origins().await.collect().await;

        assert_eq!(2, origins.len());
        assert!(origins.contains(&"snyk".to_owned()));
        assert!(origins.contains(&"osv".to_owned()));

        Ok(())
    }
}
