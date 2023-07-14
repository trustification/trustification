use actix_web::web::{self, ServiceConfig};
use actix_web::{get, HttpResponse};
use serde_json::{json, Value};

pub struct Config {
    content: Value,
}

pub async fn get_config(config: web::Data<Config>) -> HttpResponse {
    HttpResponse::Ok().json(&config.content)
}

pub(crate) fn configurator() -> anyhow::Result<impl Fn(&mut ServiceConfig) + Clone> {
    let content = serde_yaml::from_slice(include_bytes!("../config.yaml"))?;
    let config = web::Data::new(Config { content });

    Ok(move |service_config: &mut ServiceConfig| {
        service_config
            .app_data(config.clone())
            .service(web::resource("/api/v1/config").to(get_config));
    })
}
