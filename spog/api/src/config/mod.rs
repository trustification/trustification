use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use anyhow::bail;
use spog_model::config::Configuration;
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::instrument;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub struct Config {
    content: Configuration,
    source: Option<PathBuf>,
}

impl Config {
    #[instrument(skip(self), err)]
    async fn retrieve(&self, public: bool) -> anyhow::Result<Cow<'_, Configuration>> {
        Ok(match &self.source {
            Some(config) => {
                // FIXME: need to cache instead re-parsing every time
                // TODO: when we cache the result, attach a probe to it which fails if loading fails
                let content = tokio::fs::read(config).await?;
                let mut result = serde_yaml::from_slice(&content)?;
                if public {
                    result = Self::make_public(result);
                }
                Cow::Owned(result)
            }
            None => Cow::Borrowed(&self.content),
        })
    }

    fn make_public(config: Configuration) -> Configuration {
        Configuration {
            global: config.global,
            ..Default::default()
        }
    }
}

pub async fn get_config(config: &Config, public: bool) -> HttpResponse {
    match config.retrieve(public).await {
        Ok(config) => HttpResponse::Ok().json(&config),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

pub async fn get_private_config(config: web::Data<Config>) -> HttpResponse {
    get_config(&config, false).await
}

pub async fn get_public_config(config: web::Data<Config>) -> HttpResponse {
    get_config(&config, true).await
}

pub(crate) async fn configurator(
    source: Option<PathBuf>,
    auth: Option<Arc<Authenticator>>,
) -> anyhow::Result<impl Fn(&mut ServiceConfig) + Clone> {
    let content = serde_yaml::from_slice(include_bytes!("default.yaml"))?;

    // do an initial check

    let config = match source {
        Some(source) => {
            if !source.is_file() {
                bail!(
                    "Configuration file '{}' does not exist or is not a file.",
                    source.display()
                )
            }
            let config = Config {
                content,
                source: Some(source),
            };

            let _ = config.retrieve(false).await?;

            config
        }
        None => Config { content, source },
    };

    // convert to app data

    let config = web::Data::new(config);

    // configure service

    Ok(move |service_config: &mut ServiceConfig| {
        service_config
            .app_data(config.clone())
            .service(
                web::resource("/api/v1/config")
                    .wrap(new_auth!(auth.clone()))
                    .to(get_private_config),
            )
            .service(web::resource("/api/v1/config/public").to(get_public_config));
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// ensure that the default configuration parses
    fn parse_default() {
        let _config: Configuration = serde_yaml::from_slice(include_bytes!("default.yaml")).unwrap();
    }
}
