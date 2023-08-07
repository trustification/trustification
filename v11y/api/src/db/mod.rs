use sqlx::sqlite::SqliteConnectOptions;
use sqlx::SqlitePool;
use std::str::FromStr;

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
                    modified datetime,
                    published datatime,
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
            create unique index if not exists vulnerabilities_pk ON vulnerabilities ( id ) ;
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
}
