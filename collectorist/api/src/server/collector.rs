use actix_web::{get, web, HttpResponse, Responder};

use crate::state::AppState;

/// Return config for a collector
#[utoipa::path(
    get,
    tag = "collectorist",
    path = "/collector/{id}",
    responses(
        (status = 200, description = "Collector configuration located"),
        (status = BAD_REQUEST, description = "Missing valid id"),
    ),
)]
#[get("/collector/{id}")]
pub(crate) async fn collector_config(
    state: web::Data<AppState>,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    if let Some(config) = state.collectors.collector_config(id.clone()) {
        Ok(HttpResponse::Ok().json(config))
    } else {
        Ok(HttpResponse::InternalServerError().finish())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::{CollectorConfig, CollectorsConfig, Interest};
    use actix_web::test::TestRequest;
    use actix_web::{test, web, App};
    use reqwest::Url;
    use serde_json::json;
    use trustification_auth::client::NoTokenProvider;

    use crate::server::config;
    use crate::state::AppState;

    #[actix_web::test]
    async fn collector_config_round_trip() -> Result<(), anyhow::Error> {
        let json = json!(
            {
                "url": "http://mycollector.example.com/",
                "cadence": "12m",
                "interests": [ "package" ]
            }
        );

        let config: CollectorConfig = serde_json::from_str(serde_json::to_string(&json)?.as_str())?;
        assert_eq!(config.cadence, Duration::from_secs(12 * 60));
        assert_eq!(config.interests.len(), 1);

        Ok(())
    }

    #[actix_web::test]
    async fn get_collector_config() -> Result<(), anyhow::Error> {
        let state = Arc::new(
            AppState::new(
                reqwest::Client::new(),
                ".",
                &CollectorsConfig {
                    collectors: [(
                        "foo".into(),
                        CollectorConfig {
                            cadence: Duration::from_secs(600),
                            interests: vec![Interest::Package],
                            url: Url::parse("http://example.com/collector-endpoint")?,
                        },
                    )]
                    .into(),
                },
                Url::parse("http://csub.example.com/").unwrap(),
                NoTokenProvider,
            )
            .await?,
        );
        let app = test::init_service(
            App::new()
                .app_data(web::Data::from(state.clone()))
                .configure(|cfg| config(cfg, None, None)),
        )
        .await;

        let request = TestRequest::post()
            .uri("/api/v1/collector/foo")
            .set_json(json!(
                {
                    "url": "http://example.com/collector-endpoint",
                    "interests": [ "package" ]
                }
            ))
            .to_request();

        test::call_service(&app, request).await;

        {
            if let Some(config) = state.collectors.collector_config("foo".into()) {
                assert_eq!(config.url.as_str(), "http://example.com/collector-endpoint");
            } else {
                panic!("no configuration for `foo`");
            }
        }

        let request = TestRequest::get().uri("/api/v1/collector/foo").to_request();

        let config: CollectorConfig = test::call_and_read_body_json(&app, request).await;
        assert_eq!(config.url.as_str(), "http://example.com/collector-endpoint");

        Ok(())
    }
}
