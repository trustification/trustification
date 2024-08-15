use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use http::StatusCode;
use spog_model::dashboard::UserPreferences;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use trustification_common::error::ErrorInformation;

#[allow(dead_code)]
static DB_FILE_NAME: &str = "preferences.db";

#[allow(dead_code)]
pub struct Db {
    pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("data base error: {0}")]
    Db(#[from] sqlx::Error),
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::Json(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());

        match self {
            Error::Json(json) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", json),
                details: json.to_string(),
            }),
            Error::Db(db) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", db),
                details: db.to_string(),
            }),
        }
    }
}

impl Db {
    #[allow(dead_code)]
    pub async fn new(base: impl AsRef<Path>) -> Result<Self, Error> {
        let db = Self {
            pool: SqlitePool::connect_with(if cfg!(test) {
                SqliteConnectOptions::from_str(":memory:")?
            } else {
                SqliteConnectOptions::default()
                    .filename(base.as_ref().join(DB_FILE_NAME))
                    .create_if_missing(true)
            })
            .await?,
        };
        db.initialize().await?;
        Ok(db)
    }

    #[allow(dead_code)]
    async fn initialize(&self) -> Result<(), Error> {
        self.create_user_preferences_table().await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn create_user_preferences_table(&self) -> Result<(), Error> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS preferences (
                user_id TEXT,
                preference TEXT
            )"#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
                create unique index if not exists user_id_idx on preferences ( user_id ) ;
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn update_user_preferences(&self, preferences: UserPreferences) -> Result<(), Error> {
        let content = preferences.preferences.unwrap_or_default();

        sqlx::query(
            r#"
                    INSERT OR REPLACE INTO preferences ( user_id, preference)
                    VALUES ($1, $2);
            "#,
        )
        .bind(preferences.user_id)
        .bind(serde_json::to_string(&content).unwrap_or_default())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn select_preferences_by_user_id(&self, user_id: String) -> Result<UserPreferences, Error> {
        let result = sqlx::query(
            r#"
           select user_id, preference from preferences where user_id = $1;
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        if result.is_empty() {
            Ok(UserPreferences::default())
        } else {
            let p = UserPreferences {
                user_id: result[0].get("user_id"),
                preferences: serde_json::from_str(result[0].get("preference"))?,
            };
            Ok(p)
        }
    }
}
#[cfg(test)]
mod test {
    use crate::db::Db;
    use spog_model::dashboard::{Preferences, UserPreferences};
    #[actix_web::test]
    async fn update_user_preferences() -> Result<(), anyhow::Error> {
        let pre_preferences = Preferences {
            sbom1: "11".to_string(),
            sbom2: "21".to_string(),
            sbom3: "31".to_string(),
            sbom4: "41".to_string(),
        };

        let post_preferences = Preferences {
            sbom1: "1".to_string(),
            sbom2: "2".to_string(),
            sbom3: "3".to_string(),
            sbom4: "4".to_string(),
        };

        let db = Db::new(".").await?;
        db.update_user_preferences(UserPreferences {
            user_id: "xiabai".to_string(),
            preferences: Some(pre_preferences.clone()),
        })
        .await?;
        db.update_user_preferences(UserPreferences {
            user_id: "user1".to_string(),
            preferences: Some(pre_preferences.clone()),
        })
        .await?;

        let result = db.select_preferences_by_user_id("user1".to_string()).await?;
        assert_eq!("user1", result.user_id);
        assert_eq!("11".to_string(), result.preferences.unwrap_or_default().sbom1);

        db.update_user_preferences(UserPreferences {
            user_id: "user1".to_string(),
            preferences: Some(post_preferences.clone()),
        })
        .await?;

        let result = db.select_preferences_by_user_id("xiabai".to_string()).await?;
        assert_eq!("xiabai", result.user_id);

        let result = db.select_preferences_by_user_id("user1".to_string()).await?;
        assert_eq!("user1", result.user_id);
        assert_eq!("1".to_string(), result.preferences.unwrap_or_default().sbom1);
        Ok(())
    }
}
