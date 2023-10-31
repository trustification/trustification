use std::future::Future;
use std::pin::Pin;
use std::{net::TcpListener, sync::Arc};

use crate::{
    advisory,
    analyze::{self, CrdaClient},
    config, cve, endpoints,
    error::Error,
    guac::service::GuacService,
    index, package, sbom,
    service::{collectorist::CollectoristService, v11y::V11yService},
    Run,
};
use actix_web::web;
use async_trait::async_trait;
use exhort_model::AnalyzeRequest;
use futures::future::select_all;
use http::StatusCode;
use spog_model::search;
use tracing::instrument;
use trustification_analytics::Tracker;
use trustification_api::{search::SearchOptions, Apply};
use trustification_auth::{
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{TokenInjector, TokenProvider},
    swagger_ui::SwaggerUiOidc,
};
use trustification_infrastructure::{app::http::HttpServerBuilder, tracing::PropagateCurrentContext, MainContext};
use trustification_version::version;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
            crate::guac::get,
        ),
        components(
            //schemas(search::PackageSummary, search::VulnSummary, search::SearchResult<Vec<search::PackageSummary>>)
            schemas(
                search::PackageSummary,
                trustification_api::search::SearchResult<Vec<search::PackageSummary>>,
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

    pub async fn run(self, context: MainContext<()>, listener: Option<TcpListener>) -> anyhow::Result<()> {
        let provider = self.run.oidc.into_provider_or_devmode(self.run.devmode).await?;
        let state = web::Data::new(AppState {
            client: self.run.client.build_client()?,
            bombastic: self.run.bombastic_url.clone(),
            vexination: self.run.vexination_url.clone(),
            exhort: self.run.exhort_url.clone(),
            provider: provider.clone(),
        });

        let config_configurator = config::configurator(self.run.config).await?;

        let (authn, authz) = self.run.auth.split(self.run.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.run.devmode, self.run.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let crda = self.run.crda_url.map(CrdaClient::new).map(web::Data::new);
        let crda_payload_limit = self.run.crda_payload_limit;

        let end_points = endpoints::Endpoints {
            vexination: String::from(self.run.vexination_url.as_str()),
            bombastic: String::from(self.run.bombastic_url.as_str()),
            collectorist: String::from(self.run.collectorist_url.as_str()),
            v11y: String::from(self.run.v11y_url.as_str()),
        };

        let guac = web::Data::new(GuacService::new(self.run.guac_url));

        let v11y = web::Data::new(V11yService::new(
            self.run.client.build_client()?,
            self.run.v11y_url,
            provider.clone(),
        ));
        let collectorist = web::Data::new(CollectoristService::new(
            self.run.client.build_client()?,
            self.run.collectorist_url,
            provider.clone(),
        ));

        let (tracker, flusher) = Tracker::new(self.run.analytics);
        let tracker = web::Data::from(tracker);

        let mut http = HttpServerBuilder::try_from(self.run.http)?
            .tracing(self.run.infra.tracing)
            .metrics(context.metrics.registry().clone(), "spog_api")
            .authorizer(authorizer.clone())
            .configure(move |svc| {
                svc.app_data(web::Data::new(state.clone()))
                    .app_data(state.clone())
                    .app_data(guac.clone())
                    .app_data(tracker.clone())
                    .app_data(v11y.clone())
                    .app_data(collectorist.clone())
                    .configure(index::configure())
                    .configure(version::configurator(version!()))
                    .configure(endpoints::configurator(end_points.clone()))
                    .configure(sbom::configure(authenticator.clone()))
                    .configure(advisory::configure(authenticator.clone()))
                    .configure(crate::guac::configure(authenticator.clone()))
                    .configure(cve::configure(authenticator.clone()))
                    .configure(package::configure(authenticator.clone()))
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
                    svc.app_data(crda.clone())
                        .configure(analyze::configure(crda_payload_limit));
                }
            });

        if let Some(v) = listener {
            // override with provided listener
            http = http.listen(v);
        }

        let http = Box::pin(async move {
            http.run().await?;
            Ok(())
        }) as Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

        let mut tasks = vec![http];

        tasks.extend(flusher);

        // run all tasks

        let (result, _index, _others) = select_all(tasks).await;

        // return

        result
    }
}

pub struct AppState {
    client: reqwest::Client,
    pub provider: Arc<dyn TokenProvider>,
    pub bombastic: reqwest::Url,
    pub vexination: reqwest::Url,
    pub exhort: reqwest::Url,
}

impl AppState {
    #[instrument(skip(self, provider), err)]
    pub async fn get_sbom(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, Error> {
        let url = self.bombastic.join("/api/v1/sbom")?;
        let response = self
            .client
            .get(url)
            .query(&[("id", id)])
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.bytes_stream())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn search_sbom(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<bombastic_model::search::SearchResult, Error> {
        let url = self.bombastic.join("/api/v1/sbom/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<bombastic_model::prelude::SearchResult>().await?)
    }

    #[instrument(skip(self, provider), err)]
    pub async fn get_vex(
        &self,
        id: &str,
        provider: &dyn TokenProvider,
    ) -> Result<impl futures::Stream<Item = reqwest::Result<bytes::Bytes>>, Error> {
        let url = self.vexination.join("/api/v1/vex")?;
        let response = self
            .client
            .get(url)
            .query(&[("advisory", id)])
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.bytes_stream())
    }

    #[instrument(skip(self, provider), err)]
    pub async fn search_vex(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
        provider: &dyn TokenProvider,
    ) -> Result<vexination_model::search::SearchResult, Error> {
        let url = self.vexination.join("/api/v1/vex/search")?;
        let response = self
            .client
            .get(url)
            .query(&[("q", q)])
            .query(&[("offset", offset), ("limit", limit)])
            .apply(&options)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(response.json::<vexination_model::prelude::SearchResult>().await?)
    }

    #[allow(unused)]
    #[instrument(skip(self, provider), err)]
    pub async fn analyze_sbom(
        &self,
        purls: Vec<String>,
        provider: &dyn TokenProvider,
    ) -> Result<Option<exhort_model::AnalyzeResponse>, Error> {
        let url = self.exhort.join("/api/v1/analyze")?;
        let response = self
            .client
            .post(url)
            .propagate_current_context()
            .inject_token(provider)
            .await?
            .json(&AnalyzeRequest { purls })
            .send()
            .await?
            .or_status_error()
            .await?;

        Ok(Some(response.json::<exhort_model::AnalyzeResponse>().await?))
    }
}

#[async_trait]
pub trait ResponseError: Sized {
    async fn or_status_error(self) -> Result<Self, Error>;

    async fn or_status_error_opt(self) -> Result<Option<Self>, Error>;
}

#[async_trait]
impl ResponseError for reqwest::Response {
    async fn or_status_error(self) -> Result<Self, Error> {
        if self.status() == StatusCode::OK {
            Ok(self)
        } else {
            let status = self.status();
            match self.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }

    async fn or_status_error_opt(self) -> Result<Option<Self>, Error> {
        match self.status() {
            StatusCode::OK => Ok(Some(self)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let status = self.status();
                match self.text().await {
                    Ok(body) => Err(Error::Response(status, body)),
                    Err(e) => Err(Error::Request(e)),
                }
            }
        }
    }
}
