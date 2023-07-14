use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use anyhow::bail;
use spog_model::config::Configuration;
use std::borrow::Cow;
use std::path::PathBuf;

pub struct Config {
    content: Configuration,
    source: Option<PathBuf>,
}

impl Config {
    async fn retrieve(&self) -> anyhow::Result<Cow<'_, Configuration>> {
        Ok(match &self.source {
            Some(config) => {
                // FIXME: need to cache instead reparsing every time
                // TODO: when we cache the result, attach a probe to it which fails if loading fails
                let content = tokio::fs::read(config).await?;
                Cow::Owned(serde_yaml::from_slice(&content)?)
            }
            None => Cow::Borrowed(&self.content),
        })
    }
}

pub async fn get_config(config: web::Data<Config>) -> HttpResponse {
    match config.retrieve().await {
        Ok(config) => HttpResponse::Ok().json(&config),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

pub(crate) async fn configurator(source: Option<PathBuf>) -> anyhow::Result<impl Fn(&mut ServiceConfig) + Clone> {
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

            let _ = config.retrieve().await?;

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
            .service(web::resource("/api/v1/config").to(get_config));
    })
}
