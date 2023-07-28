use std::{net::TcpListener, sync::Arc};

use actix_cors::Cors;
use actix_web::{web, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use anyhow::anyhow;
use http::StatusCode;
use prometheus::Registry;
use spog_model::search;
use trustification_api::{search::SearchOptions, Apply};
use trustification_auth::Authenticator;
use trustification_infrastructure::app::{new_app, AppOptions};
use trustification_version::version;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{advisory, config, index, sbom, Run};

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
        let openapi = ApiDoc::openapi();

        let state = configure(&self.run)?;

        let http_metrics = PrometheusMetricsBuilder::new("spog_api")
            .registry(registry.clone())
            .build()
            .map_err(|_| anyhow!("Error registering HTTP metrics"))?;

        let config_configurator = config::configurator(self.run.config).await?;

        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(self.run.oidc).await?.map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let mut srv = HttpServer::new(move || {
            let http_metrics = http_metrics.clone();
            let state = state.clone();
            let cors = Cors::permissive();
            let authenticator = authenticator.clone();

            new_app(AppOptions {
                cors: Some(cors),
                metrics: Some(http_metrics),
                authenticator: authenticator.clone(),
            })
            .app_data(web::Data::new(state))
            .configure(index::configure())
            .configure(version::configurator(version!()))
            .configure(sbom::configure())
            .configure(advisory::configure())
            .configure(config_configurator.clone())
            //.configure(crate::vulnerability::configure())
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
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
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        let response = self.client.get(url).query(&[("id", id)]).send().await?;
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
    ) -> Result<bombastic_model::search::SearchResult, anyhow::Error> {
        let url = self.bombastic.join("/api/v1/sbom/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
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
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        let response = self.client.get(url).query(&[("advisory", id)]).send().await?;
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
    ) -> Result<vexination_model::search::SearchResult, anyhow::Error> {
        let url = self.vexination.join("/api/v1/vex/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
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
