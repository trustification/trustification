use std::collections::HashSet;
use std::str::FromStr;

use futures::Stream;
use futures::StreamExt;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

use v11y_client::{Reference, ScoreType, Severity, Vulnerability};

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
        self.create_references_table().await?;
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
                    origin text not null,
                    type text not null,
                    score float not null,
                    additional text,
                    primary key (vulnerability_id, origin, type)

                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'severities_pk'");
        sqlx::query(
            r#"
            create index if not exists severities_pk ON severities ( vulnerability_id, origin, type ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            create index if not exists severities_pk ON severities ( vulnerability_id, origin, type ) ;
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
                    origin text not null,
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
                    origin text not null,
                    related text not null,
                    primary key (vulnerability_id, origin, related)

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
                    origin not null,
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
            r#"create table if not exists refs (
                    vulnerability_id text not null,
                    origin text not null,
                    type text not null,
                    url text not null,
                    primary key (vulnerability_id, origin, type, url)
                )"#,
        )
        .execute(&self.pool)
        .await?;

        log::debug!("create index 'references_by_id'");
        sqlx::query(
            r#"
            create index if not exists references_by_id ON refs ( vulnerability_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn ingest(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        self.ingest_vulnerability(vuln).await?;
        self.ingest_severities(vuln).await?;
        self.ingest_related(vuln).await?;
        self.ingest_references(vuln).await?;
        self.ingest_aliases(vuln).await?;
        Ok(())
    }

    pub async fn get(&self, id: &str, origin: Option<String>) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let query = match origin {
            Some(origin) => {
                sqlx::query(
                    r#"
            select
                vulnerabilities.id,
                vulnerabilities.origin,
                vulnerabilities.modified,
                vulnerabilities.published,
                vulnerabilities.withdrawn,
                vulnerabilities.summary,
                vulnerabilities.details,
                aliases.alias,
                related.related,
                refs.type,
                refs.url,
                severities.type as score_type,
                severities.score,
                severities.additional
            from
                vulnerabilities
            left join
                aliases on aliases.vulnerability_id = vulnerabilities.id and aliases.origin = vulnerabilities.origin
            left join
                related on related.vulnerability_id = vulnerabilities.id and related.origin = vulnerabilities.origin
            left join
                refs on refs.vulnerability_id = vulnerabilities.id and refs.origin = vulnerabilities.origin
            left join
                severities on severities.vulnerability_id = vulnerabilities.id and severities.origin = vulnerabilities.origin
            where
                vulnerabilities.id = $1 and vulnerabilities.origin = $2
            order by
                vulnerabilities.origin
            "#,
                )
                    .bind(id)
                    .bind(origin)
            }

            None => {
                sqlx::query(
                    r#"
            select
                vulnerabilities.id,
                vulnerabilities.origin,
                vulnerabilities.modified,
                vulnerabilities.published,
                vulnerabilities.withdrawn,
                vulnerabilities.summary,
                vulnerabilities.details,
                aliases.alias,
                related.related,
                refs.type,
                refs.url,
                severities.type as score_type,
                severities.score,
                severities.additional
            from
                vulnerabilities
            left join
                aliases on aliases.vulnerability_id = vulnerabilities.id and aliases.origin = vulnerabilities.origin
            left join
                related on related.vulnerability_id = vulnerabilities.id and related.origin = vulnerabilities.origin
            left join
                refs on refs.vulnerability_id = vulnerabilities.id and refs.origin = vulnerabilities.origin
            left join
                severities on severities.vulnerability_id = vulnerabilities.id and severities.origin = vulnerabilities.origin
            where
                vulnerabilities.id = $1
            order by
                vulnerabilities.origin
            "#,
                ).bind(id)
            }
        };

        let vulns = query
            .fetch(&self.pool)
            .fold(
                (vec![], None::<Vulnerability>),
                |(mut accum, mut cur), row| async move {
                    row.ok()
                        .map(|row| {
                            if cur.is_none() || cur.as_ref().unwrap().origin != row.get::<String, _>("origin") {
                                let vuln = Vulnerability {
                                    origin: row.get("origin"),
                                    id: row.get("id"),
                                    modified: row.get("modified"),
                                    published: row.get("published"),
                                    withdrawn: row.get("withdrawn"),
                                    summary: row.get("summary"),
                                    details: row.get("details"),
                                    aliases: HashSet::default(),
                                    affected: vec![],
                                    severities: HashSet::default(),
                                    related: HashSet::default(),
                                    references: HashSet::default(),
                                };

                                if let Some(cur) = cur.take() {
                                    accum.push(cur);
                                }

                                cur.replace(vuln);
                            }

                            if let Some(cur_vuln) = &mut cur {
                                if cur_vuln.origin == row.get::<String, _>("origin") {
                                    // continue to populate
                                    let alias = row.get::<String, _>("alias");
                                    if !alias.is_empty() && !cur_vuln.aliases.contains(&alias) {
                                        cur_vuln.aliases.insert(alias);
                                    }

                                    let related = row.get::<String, _>("related");
                                    if !related.is_empty() && !cur_vuln.related.contains(&related) {
                                        cur_vuln.related.insert(related);
                                    }

                                    let (ty, url) = (row.get::<String, _>("type"), row.get::<String, _>("url"));
                                    if !url.is_empty() {
                                        let reference = Reference { r#type: ty, url };

                                        if !cur_vuln.references.contains(&reference) {
                                            cur_vuln.references.insert(reference);
                                        }
                                    }

                                    let (ty, score, additional) = (
                                        row.get::<String, _>("score_type"),
                                        row.get::<f32, _>("score"),
                                        row.get::<String, _>("additional"),
                                    );

                                    if !ty.is_empty() {
                                        let additional = if additional.is_empty() { None } else { Some(additional) };
                                        let severity = Severity {
                                            r#type: ScoreType::from(ty),
                                            score,
                                            additional,
                                        };

                                        if !cur_vuln.severities.contains(&severity) {
                                            cur_vuln.severities.insert(severity);
                                        }
                                    }
                                } else {
                                    let vuln = cur.take().unwrap();
                                    accum.push(vuln)
                                }
                            }
                        })
                        .unwrap();
                    (accum, cur)
                },
            )
            .await;

        let (mut vulns, cur) = vulns;

        if let Some(cur) = cur {
            vulns.push(cur);
        }

        Ok(vulns)
    }

    async fn ingest_vulnerability(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        sqlx::query(
            r#"
                insert or replace into vulnerabilities (
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

    async fn ingest_severities(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        for severity in &vuln.severities {
            sqlx::query(
                r#"
            insert into severities (
                vulnerability_id, origin, type, score, additional
            ) values (
                $1, $2, $3, $4, $5
            ) on conflict (vulnerability_id, origin, type) do update
                set
                    score = excluded.score,
                    additional = excluded.additional
            "#,
            )
            .bind(vuln.id.clone())
            .bind(vuln.origin.clone())
            .bind(severity.r#type.to_string())
            .bind(severity.score)
            .bind(severity.additional.clone())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn ingest_related(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        for related in &vuln.related {
            sqlx::query(
                r#"
            insert into related (
                vulnerability_id, origin, related
            ) values (
                $1, $2, $3
            ) on conflict (vulnerability_id, origin, related) do update
                set
                    related = excluded.related
                "#,
            )
            .bind(vuln.id.clone())
            .bind(vuln.origin.clone())
            .bind(related)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn ingest_references(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        for reference in &vuln.references {
            sqlx::query(
                r#"
            insert or ignore into refs (
                vulnerability_id, origin, type, url
            ) values (
                $1, $2, $3, $4
            )
                "#,
            )
            .bind(vuln.id.clone())
            .bind(vuln.origin.clone())
            .bind(reference.r#type.clone())
            .bind(reference.url.clone())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn ingest_aliases(&self, vuln: &Vulnerability) -> Result<(), anyhow::Error> {
        for alias in &vuln.aliases {
            sqlx::query(
                r#"
            insert or ignore into aliases (
                vulnerability_id, origin, alias
            ) values (
                $1, $2, $3
            )
                "#,
            )
            .bind(vuln.id.clone())
            .bind(vuln.origin.clone())
            .bind(alias.clone())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    #[allow(unused)]
    pub async fn get_known_ids(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"select distinct id from vulnerabilities"#)
            .fetch(&self.pool)
            .filter_map(|row| async move { row.ok().map(|row| row.get("id")) })
    }

    #[allow(unused)]
    pub async fn get_known_origins(&self) -> impl Stream<Item = String> {
        sqlx::query(r#"select distinct origin from vulnerabilities"#)
            .fetch(&self.pool)
            .filter_map(|row| async move { row.ok().map(|row| row.get("origin")) })
    }

    pub async fn get_severities<'s>(
        &'s self,
        id: &'s str,
        origin: Option<String>,
    ) -> impl Stream<Item = (String, Severity)> + 's {
        let query = if let Some(origin) = origin {
            sqlx::query(
                r#"
                select
                    origin, type, score, additional
                from
                    severities
                where
                    vulnerability_id = $1 and origin = $2
                "#,
            )
            .bind(id)
            .bind(origin)
        } else {
            sqlx::query(
                r#"
                select
                    origin, type, score, additional
                from
                    severities
                where
                    vulnerability_id = $1
                order by
                    origin
                "#,
            )
            .bind(id)
        };

        query.fetch(&self.pool).filter_map(|row| async move {
            row.ok().map(|row| {
                (
                    row.get("origin"),
                    Severity {
                        r#type: ScoreType::from(row.get::<String, _>("type")),
                        score: row.get("score"),
                        additional: row.get("additional"),
                    },
                )
            })
        })
    }

    pub async fn get_related<'s>(
        &'s self,
        id: &'s str,
        origin: Option<String>,
    ) -> impl Stream<Item = (String, String)> + 's {
        let query = if let Some(origin) = origin {
            sqlx::query(
                r#"
                select
                    origin, related
                from
                    related
                where
                    vulnerability_id = $1 and origin = $2
                "#,
            )
            .bind(id)
            .bind(origin)
        } else {
            sqlx::query(
                r#"
                select
                    origin, related
                from
                    related
                where
                    vulnerability_id = $1
                order by
                    origin
                "#,
            )
            .bind(id)
        };

        query
            .fetch(&self.pool)
            .filter_map(|row| async move { row.ok().map(|row| (row.get("origin"), row.get("related"))) })
    }

    pub async fn get_references<'s>(
        &'s self,
        id: &'s str,
        r#type: Option<String>,
        origin: Option<String>,
    ) -> impl Stream<Item = (String, Reference)> + 's {
        let query = match (origin, r#type) {
            (Some(origin), Some(ty)) => sqlx::query(
                r#"
                select
                    origin, type, url
                from
                    refs
                where
                    vulnerability_id = $1 and origin = $2 and type = $3
                "#,
            )
            .bind(id)
            .bind(origin)
            .bind(ty),

            (Some(origin), None) => sqlx::query(
                r#"
                select
                    origin, type, url
                from
                    refs
                where
                    vulnerability_id = $1 and origin = $2
                "#,
            )
            .bind(id)
            .bind(origin),

            (None, Some(ty)) => sqlx::query(
                r#"
                select
                    origin, type, url
                from
                    refs
                where
                    vulnerability_id = $1 and type = $2
                order by
                    origin
                "#,
            )
            .bind(id)
            .bind(ty),

            (None, None) => sqlx::query(
                r#"
                select
                    origin, type, url
                from
                    refs
                where
                    vulnerability_id = $1
                order by
                    origin
                "#,
            )
            .bind(id),
        };

        query.fetch(&self.pool).filter_map(|row| async move {
            row.ok().map(|row| {
                (
                    row.get("origin"),
                    Reference {
                        r#type: row.get("type"),
                        url: row.get("url"),
                    },
                )
            })
        })
    }
}

#[cfg(test)]
mod test {
    use futures::StreamExt;
    use std::collections::HashSet;

    use v11y_client::{Reference, ScoreType, Severity, Vulnerability};

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
            aliases: HashSet::default(),
            severities: HashSet::default(),
            affected: vec![],
            related: HashSet::default(),
            references: HashSet::default(),
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
            aliases: HashSet::default(),
            severities: HashSet::default(),
            affected: vec![],
            related: HashSet::default(),
            references: HashSet::default(),
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
            aliases: HashSet::default(),
            severities: HashSet::default(),
            affected: vec![],
            related: HashSet::default(),
            references: HashSet::default(),
        };

        db.ingest(&vuln).await?;

        let ids: Vec<_> = db.get_known_ids().await.collect().await;

        assert_eq!(2, ids.len());
        assert!(ids.contains(&"CVE-123".to_owned()));
        assert!(ids.contains(&"CVE-345".to_owned()));

        let origins: Vec<_> = db.get_known_origins().await.collect().await;

        assert_eq!(2, origins.len());
        assert!(origins.contains(&"snyk".to_owned()));
        assert!(origins.contains(&"osv".to_owned()));

        Ok(())
    }

    #[tokio::test]
    async fn ingest_maximal() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        let osv_vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: HashSet::from(["GHSA-foo-ghz".to_string()]),
            severities: HashSet::from([Severity {
                r#type: ScoreType::Cvss3,
                score: 6.8,
                additional: Some("n:4/v:2".to_string()),
            }]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string()]),
            references: HashSet::from([Reference {
                r#type: "ADVISORY".to_string(),
                url: "http://osv.dev/foo".to_string(),
            }]),
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
            aliases: HashSet::from(["GHSA-foo-ghz".to_string()]),
            severities: HashSet::from([Severity {
                r#type: ScoreType::Cvss3,
                score: 7.8,
                additional: Some("n:1/v:2".to_string()),
            }]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string(), "CVE-42".to_string()]),
            references: HashSet::from([Reference {
                r#type: "WEB".to_string(),
                url: "http://snyk.com/foo".to_string(),
            }]),
        };

        db.ingest(&snyk_vuln).await?;
        let result = db.get("CVE-123", Some("snyk".to_string())).await?;
        assert_eq!(1, result.len());
        assert_eq!(result[0], snyk_vuln);

        let result: Vec<_> = db
            .get_severities("CVE-123", Some("osv".to_string()))
            .await
            .collect()
            .await;

        assert_eq!(1, result.len());

        let result = &result[0];

        assert_eq!("osv", result.0);
        assert_eq!(6.8, result.1.score);
        assert_eq!(ScoreType::Cvss3, result.1.r#type);
        assert_eq!(Some("n:4/v:2".to_string()), result.1.additional);

        let result: Vec<_> = db
            .get_severities("CVE-123", Some("snyk".to_string()))
            .await
            .collect()
            .await;

        assert_eq!(1, result.len());

        let result = &result[0];

        assert_eq!("snyk", result.0);
        assert_eq!(7.8, result.1.score);
        assert_eq!(ScoreType::Cvss3, result.1.r#type);
        assert_eq!(Some("n:1/v:2".to_string()), result.1.additional);

        let result: Vec<_> = db.get_severities("CVE-123", None).await.collect().await;

        assert_eq!(2, result.len());

        let result: Vec<_> = db.get_related("CVE-123", Some("osv".to_string())).await.collect().await;
        assert_eq!(1, result.len());

        let result: Vec<_> = db
            .get_related("CVE-123", Some("snyk".to_string()))
            .await
            .collect()
            .await;
        assert_eq!(2, result.len());

        let result: Vec<_> = db.get_related("CVE-123", None).await.collect().await;
        assert_eq!(3, result.len());

        let result: Vec<_> = db.get_references("CVE-123", None, None).await.collect().await;
        assert_eq!(2, result.len());

        let result: Vec<_> = db
            .get_references("CVE-123", None, Some("osv".to_string()))
            .await
            .collect()
            .await;
        assert_eq!(1, result.len());

        assert_eq!("ADVISORY", result[0].1.r#type);
        assert_eq!("http://osv.dev/foo", result[0].1.url);

        let result: Vec<_> = db
            .get_references("CVE-123", None, Some("snyk".to_string()))
            .await
            .collect()
            .await;
        assert_eq!(1, result.len());

        assert_eq!("WEB", result[0].1.r#type);
        assert_eq!("http://snyk.com/foo", result[0].1.url);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_updated_severities() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: HashSet::from(["GHSA-foo-ghz".to_string()]),
            severities: HashSet::from([Severity {
                r#type: ScoreType::Cvss3,
                score: 6.8,
                additional: Some("n:4/v:2".to_string()),
            }]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string(), "CVE-42".to_string()]),
            references: HashSet::default(),
        };

        db.ingest(&vuln).await?;

        let result: Vec<_> = db
            .get_severities("CVE-123", Some("osv".to_string()))
            .await
            .collect()
            .await;

        assert_eq!(1, result.len());

        let result = &result[0];

        assert_eq!("osv", result.0);
        assert_eq!(6.8, result.1.score);
        assert_eq!(ScoreType::Cvss3, result.1.r#type);
        assert_eq!(Some("n:4/v:2".to_string()), result.1.additional);

        let vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: HashSet::from(["GHSA-foo-ghz".to_string()]),
            severities: HashSet::from([
                Severity {
                    r#type: ScoreType::Cvss3,
                    score: 9.8,
                    additional: Some("n:4/v:2".to_string()),
                },
                Severity {
                    r#type: ScoreType::Cvss4,
                    score: 7.3,
                    additional: None,
                },
            ]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string(), "CVE-42".to_string()]),
            references: HashSet::default(),
        };

        db.ingest(&vuln).await?;

        let result: Vec<_> = db
            .get_severities("CVE-123", Some("osv".to_string()))
            .await
            .collect()
            .await;

        assert_eq!(2, result.len());

        for (_, severity) in result {
            match severity.r#type {
                ScoreType::Cvss3 => {
                    assert_eq!(9.8, severity.score)
                }
                ScoreType::Cvss4 => {
                    assert_eq!(7.3, severity.score)
                }
                ScoreType::Unknown => panic!("unexpected unknown"),
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn get_without_origin() -> Result<(), anyhow::Error> {
        let db = Db::new().await?;

        let osv_vuln = Vulnerability {
            origin: "osv".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: HashSet::default(),
            severities: HashSet::from([Severity {
                r#type: ScoreType::Cvss3,
                score: 6.8,
                additional: Some("n:4/v:2".to_string()),
            }]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string()]),
            references: HashSet::from([Reference {
                r#type: "ADVISORY".to_string(),
                url: "http://osv.dev/foo".to_string(),
            }]),
        };

        db.ingest(&osv_vuln).await?;

        let snyk_vuln = Vulnerability {
            origin: "snyk".to_string(),
            id: "CVE-123".to_string(),
            modified: "2023-08-08T18:17:02Z".parse()?,
            published: "2023-08-08T18:17:02Z".parse()?,
            withdrawn: None,
            summary: "Summary".to_string(),
            details: "Some\ndetails".to_string(),
            aliases: HashSet::from(["GHSA-foo-ghz".to_string()]),
            severities: HashSet::from([Severity {
                r#type: ScoreType::Cvss3,
                score: 7.8,
                additional: Some("n:1/v:2".to_string()),
            }]),
            affected: vec![],
            related: HashSet::from(["CVE-8675".to_string(), "CVE-42".to_string()]),
            references: HashSet::from([Reference {
                r#type: "WEB".to_string(),
                url: "http://snyk.com/foo".to_string(),
            }]),
        };

        db.ingest(&snyk_vuln).await?;

        let result = db.get("CVE-123", None).await?;

        assert!(result.contains(&osv_vuln));
        assert!(result.contains(&snyk_vuln));

        Ok(())
    }
}
