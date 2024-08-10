use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use utoipa::ToSchema;

#[allow(dead_code)]
static DB_FILE_NAME: &str = "user_preferences.db";

#[derive(Clone, Debug, PartialEq, Eq, ToSchema, Serialize, Deserialize)]
pub struct UserPreferences {
    user_id: String,
    preferences: Option<String>,
}

#[allow(dead_code)]
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    #[allow(dead_code)]
    pub async fn new(base: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
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
    async fn initialize(&self) -> Result<(), anyhow::Error> {
        self.create_user_preferences_table().await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn create_user_preferences_table(&self) -> Result<(), anyhow::Error> {
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
    pub async fn update_user_preferences(&self, preferences: UserPreferences) -> Result<(), anyhow::Error> {
        let content = preferences.preferences.unwrap_or_default();

        sqlx::query(
            r#"
                    INSERT OR REPLACE INTO preferences ( user_id, preference)
                    VALUES ($1, $2);
            "#,
        )
        .bind(preferences.user_id)
        .bind(content)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    #[allow(dead_code)]
    pub async fn select_preferences_by_user_id(&self, user_id: String) -> Result<UserPreferences, anyhow::Error> {
        let result = sqlx::query(
            r#"
           select user_id, preference from preferences where user_id = $1;
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        let p = UserPreferences {
            user_id: result.get("user_id"),
            preferences: result.get("preference"),
        };
        Ok(p)
    }
}
#[cfg(test)]
mod test {
    use crate::db::{Db, UserPreferences};
    #[actix_web::test]
    async fn update_user_preferences() -> Result<(), anyhow::Error> {
        let db = Db::new(".").await?;
        db.update_user_preferences(UserPreferences {
            user_id: "xiabai".to_string(),
            preferences: Some("some fileds".to_string()),
        })
        .await?;
        db.update_user_preferences(UserPreferences {
            user_id: "user1".to_string(),
            preferences: Some("some field".to_string()),
        })
        .await?;

        let result = db.select_preferences_by_user_id("user1".to_string()).await?;
        assert_eq!("user1", result.user_id);
        assert_eq!("some field", result.preferences.unwrap_or_else(|| "".to_string()));

        db.update_user_preferences(UserPreferences {
            user_id: "user1".to_string(),
            preferences: Some("changed".to_string()),
        })
        .await?;

        let result = db.select_preferences_by_user_id("xiabai".to_string()).await?;
        assert_eq!("xiabai", result.user_id);

        let result = db.select_preferences_by_user_id("user1".to_string()).await?;
        assert_eq!("user1", result.user_id);
        assert_eq!("changed", result.preferences.unwrap_or_else(|| "".to_string()));
        Ok(())
    }
}
