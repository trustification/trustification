use std::{net::TcpListener, sync::Arc};

use actix_cors::Cors;
use actix_web::{web, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use anyhow::anyhow;
use http::StatusCode;
use prometheus::Registry;
use spog_model::search;
use trustification_api::{search::SearchOptions, Apply};
use trustification_auth::{
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{TokenInjector, TokenProvider},
    swagger_ui::SwaggerUiOidc,
};
use trustification_infrastructure::app::{new_app, AppOptions};
use trustification_version::version;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::analyze::CrdaClient;
use crate::{advisory, analyze, config, index, sbom, Run};

pub struct Server {
    run: Run,
}

#[derive(OpenApi)]
#[openapi(
        paths(
            sbom::get,
            sbom::search,
            advisory::get,
            advisory::search,
            trustification_version::version::version_fn,
            //vulnerability::search,
        ),
        components(
            //schemas(search::PackageSummary, search::VulnSummary, search::SearchResult<Vec<search::PackageSummary>>)
            schemas(
                search::PackageSummary,
                search::SearchResult<Vec<search::PackageSummary>>,
                trustification_version::VersionInformation,
                trustification_version::Version,
                trustification_version::Git,
                trustification_version::Build,
            )
        ),
        tags(
            (name = "package", description = "Package endpoints"),
            (name = "advisory", description = "Advisory endpoints"),
          //  (name = "vulnerability", description = "Vulnerability endpoints"),
        ),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(run: Run) -> Self {
        Self { run }
    }

    pub async fn run(self, registry: &Registry, listener: Option<TcpListener>) -> anyhow::Result<()> {
        let state = configure(&self.run)?;

        let http_metrics = PrometheusMetricsBuilder::new("spog_api")
            .registry(registry.clone())
            .build()
            .map_err(|_| anyhow!("Error registering HTTP metrics"))?;

        let config_configurator = config::configurator(self.run.config).await?;

        let authenticator: Option<Arc<Authenticator>> =
            Authenticator::from_devmode_or_config(self.run.devmode, self.run.oidc)
                .await?
                .map(Arc::new);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.run.devmode, self.run.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let crda = self.run.crda_url.map(CrdaClient::new);
        let crda_payload_limit = self.run.crda_payload_limit;

        let mut srv = HttpServer::new(move || {
            let state = state.clone();

            let http_metrics = http_metrics.clone();
            let cors = Cors::permissive();
            let authenticator = authenticator.clone();
            let swagger_oidc = swagger_oidc.clone();

            let mut app = new_app(AppOptions {
                cors: Some(cors),
                metrics: Some(http_metrics),
                authenticator: None, // we map this explicitly
                authorizer: if self.run.devmode {
                    Authorizer::Disabled
                } else {
                    Authorizer::Enabled
                },
            })
            .app_data(web::Data::new(state))
            .configure(index::configure())
            .configure(version::configurator(version!()))
            .configure(sbom::configure(authenticator.clone()))
            .configure(advisory::configure(authenticator.clone()))
            .configure(config_configurator.clone())
            .service({
                let mut openapi = ApiDoc::openapi();
                let mut swagger = SwaggerUi::new("/swagger-ui/{_:.*}");

                if let Some(swagger_ui_oidc) = &swagger_oidc {
                    swagger = swagger_ui_oidc.apply(swagger, &mut openapi);
                }

                swagger.url("/openapi.json", openapi)
            });

            if let Some(crda) = &crda {
                app = app
                    .app_data(web::Data::new(crda.clone()))
                    .configure(analyze::configure(crda_payload_limit));
            }

            app
        });
        srv = match listener {
            Some(v) => srv.listen(v)?,
            None => srv.bind((self.run.bind, self.run.port))?,
        };
        srv.run().await?;
        Ok(())
    }
}

pub struct AppState {
    client: reqwest::Client,
    pub bombastic: reqwest::Url,
    pub vexination: reqwest::Url,
}

impl AppState {
    pub async fn get_sbom(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        let response = self
            .client
            .get(url)
            .query(&[("id", id)])
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn search_sbom(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<bombastic_model::search::SearchResult, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<bombastic_model::prelude::SearchResult>().await?)
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn get_vex(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        let response = self
            .client
            .get(url)
            .query(&[("advisory", id)])
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            Err(anyhow::anyhow!(
                "Error querying bombastic service: {:?}",
                response.status()
            ))
        }
    }

    pub async fn search_vex(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<vexination_model::search::SearchResult, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<vexination_model::prelude::SearchResult>().await?)
        } else {
            Err(anyhow::anyhow!(
                "Error querying vexination service: {:?}",
                response.status()
            ))
        }
    }
}

pub type SharedState = Arc<AppState>;

pub(crate) fn configure(run: &Run) -> anyhow::Result<Arc<AppState>> {
    let state = Arc::new(AppState {
        client: reqwest::Client::new(),
        bombastic: run.bombastic_url.clone(),
        vexination: run.vexination_url.clone(),
    });
    Ok(state)
}
