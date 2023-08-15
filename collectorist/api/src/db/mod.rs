use std::str::FromStr;

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

static DB_FILE_NAME: &str = "collectorist.db";

pub struct Db {
    pool: SqlitePool,
}

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

    pub async fn insert_purl(&self, purl: &str) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"insert or ignore into purls (purl) values ($1)
            "#,
        )
        .bind(purl.clone())
        .bind(purl.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_vulnerability(&self, vuln_id: &str) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"insert or ignore into vulnerabilities (id) values ($1)
            "#,
        )
        .bind(vuln_id.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[allow(unused)]
    pub async fn get_purls(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"select purl from purls"#)
            .fetch(&self.pool)
            .filter_map(|row| async move {
                if let Ok(row) = row {
                    Some(row.get::<String, _>("purl"))
                } else {
                    None
                }
            })
    }

    pub async fn update_purl_scan_time(&self, collector_id: &str, purl: &str) -> Result<(), anyhow::Error> {
        sqlx::query(r#"replace into collector_purls (collector, purl, timestamp) VALUES ($1, $2, $3)"#)
            .bind(collector_id.clone())
            .bind(purl)
            .bind(Utc::now())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn update_vulnerability_scan_time(&self, collector_id: &str, vuln_id: &str) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"replace into collector_vulnerabilities (collector, vulnerability_id, timestamp) VALUES ($1, $2, $3)"#,
        )
        .bind(collector_id.clone())
        .bind(vuln_id)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[allow(unused)]
    pub async fn get_purl_scan_time(
        &self,
        collector_id: &str,
        purl: String,
    ) -> Result<Option<DateTime<Utc>>, anyhow::Error> {
        Ok(sqlx::query(
            r#"
            select
                timestamp
            from
                collector_purls
            where
                collector = $1 and purl = $2"#,
        )
        .bind(collector_id.clone())
        .bind(purl.clone())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| row.get::<DateTime<Utc>, _>("timestamp")))
    }

    pub async fn get_purls_to_scan<'f>(
        &'f self,
        collector_id: &'f str,
        since: DateTime<Utc>,
        limit: u32,
    ) -> impl Stream<Item = String> + 'f {
        sqlx::query(
            r#"
            select
                purls.purl
            from
                purls
            left join
                collector_purls
            on
                purls.purl = collector_purls.purl
            where
                collector_purls.timestamp is null or collector_purls.timestamp < $2
            limit
                $3
            "#,
        )
        .bind(collector_id)
        .bind(since)
        .bind(limit)
        .fetch(&self.pool)
        .filter_map(|row| async move {
            if let Ok(row) = row {
                Some(row.get::<String, _>("purl"))
            } else {
                None
            }
        })
    }

    #[allow(unused)]
    pub async fn get_vulnerabilities_to_scan<'f>(
        &'f self,
        collector_id: &'f str,
        since: DateTime<Utc>,
        limit: u32,
    ) -> impl Stream<Item = String> + 'f {
        sqlx::query(
            r#"
            select
                vulnerabilities.id
            from
                vulnerabilities
            left join
                collector_vulnerabilities
            on
                vulnerabilities.id = collector_vulnerabilities.vulnerability_id
            where
                collector_vulnerabilities.timestamp is null or collector_vulnerabilities.timestamp < $2
            limit
                $3
            "#,
        )
        .bind(collector_id)
        .bind(since)
        .bind(limit)
        .fetch(&self.pool)
        .filter_map(|row| async move {
            if let Ok(row) = row {
                Some(row.get::<String, _>("id"))
            } else {
                None
            }
        })
    }

    async fn initialize(&self) -> Result<(), anyhow::Error> {
        self.create_purls_table().await?;
        self.create_vulnerabilities_table().await?;
        self.create_collector_purls_table().await?;
        self.create_collector_vulnerabilities_table().await?;
        Ok(())
    }

    async fn create_purls_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"create table if not exists purls (
                    purl text
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create unique index if not exists purl_idx on purls ( purl ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_vulnerabilities_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"create table if not exists vulnerabilities (
                    id text
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create unique index if not exists vulnerability_idx on vulnerabilities ( id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_collector_purls_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"create table if not exists collector_purls (
                    collector text,
                    purl text,
                    timestamp datetime
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create unique index if not exists collector_purl_idx ON collector_purls ( purl ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_collector_vulnerabilities_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"create table if not exists collector_vulnerabilities (
                    collector text,
                    vulnerability_id text,
                    timestamp datetime
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create unique index if not exists collector_vulnerability_idx ON collector_vulnerabilities ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::thread::sleep;

    use chrono::{Duration, Utc};
    use futures::StreamExt;

    use crate::db::Db;

    #[actix_web::test]
    async fn insert_purl() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        db.insert_purl("bob").await?;
        db.insert_purl("bob").await?;
        db.insert_purl("bob").await?;
        db.insert_purl("bob").await?;
        db.insert_purl("jens").await?;
        db.insert_purl("jim").await?;
        db.insert_purl("jim").await?;
        db.insert_purl("jim").await?;

        let result = Box::pin(db.get_purls().await);
        let purls: Vec<_> = result.collect().await;

        assert_eq!(3, purls.len());
        assert!(purls.contains(&"jens".to_owned()));
        assert!(purls.contains(&"jim".to_owned()));
        assert!(purls.contains(&"bob".to_owned()));
        Ok(())
    }

    #[actix_web::test]
    async fn update_purl_scan_time() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        db.insert_purl("not-scanned").await?;
        db.insert_purl("is-scanned").await?;
        db.update_purl_scan_time("test-scanner", "is-scanned").await?;

        sleep(Duration::seconds(2).to_std()?);

        let result = Box::pin(
            db.get_purls_to_scan("test-scanner", Utc::now() - Duration::minutes(1), 10)
                .await,
        );
        let purls: Vec<_> = result.collect().await;

        assert_eq!(1, purls.len());
        assert!(purls.contains(&"not-scanned".to_owned()));

        Ok(())
    }
}
