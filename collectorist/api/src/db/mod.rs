use std::str::FromStr;

use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

static DB_FILE_NAME: &str = "gatherer.db";

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
            r#"INSERT OR IGNORE INTO purls (purl) VALUES ($1)
            "#,
        )
        .bind(purl.clone())
        .bind(purl.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[allow(unused)]
    pub async fn get_purls(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"SELECT purl FROM purls"#)
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
        sqlx::query(r#"REPLACE INTO collector (collector, purl, timestamp) VALUES ($1, $2, $3)"#)
            .bind(collector_id.clone())
            .bind(purl)
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
            SELECT
                timestamp
            FROM
                collector
            WHERE
                collector = $1 AND purl = $2"#,
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
            SELECT
                purls.purl
            FROM
                purls
            LEFT JOIN
                collector
            ON
                purls.purl = collector.purl
            WHERE
                collector.timestamp IS NULL OR collector.timestamp < $2
            LIMIT
                $3
            "#,
        )
        /*
        sqlx::query(
            r#"
            SELECT
                purl, timestamp
            FROM
                collector
            WHERE
                collector = $1 AND timestamp < $2
            UNION
            SELECT
                purl, 0
            FROM
                purls
            ORDER BY
                collector.timestamp ASC
            LIMIT
                $3
            "#,
        )
        */
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

    async fn initialize(&self) -> Result<(), anyhow::Error> {
        self.create_purls_table().await?;
        self.create_collector_table().await?;
        Ok(())
    }

    async fn create_purls_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS purls (
                    purl text
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS purl_idx ON purls ( purl ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn create_collector_table(&self) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS collector (
                    collector text,
                    purl text,
                    timestamp datetime
                )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS collector_idx ON collector ( purl ) ;
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
