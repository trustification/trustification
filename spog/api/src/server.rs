use std::future::Future;
use std::pin::Pin;
use std::{net::TcpListener, sync::Arc};

use crate::{
    advisory,
    analyze::{self, CrdaClient},
    config, cve,
    guac::service::GuacService,
    index, sbom,
    service::{collectorist, collectorist::CollectoristService, v11y, v11y::V11yService},
    Run,
};
use actix_web::{http::header::ContentType, web, HttpResponse};
use futures::future::select_all;
use http::StatusCode;
use spog_model::search;
use trustification_analytics::Tracker;
use trustification_api::{search::SearchOptions, Apply};
use trustification_auth::{
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{Error as AuthClientError, TokenInjector, TokenProvider},
    swagger_ui::SwaggerUiOidc,
};
use trustification_common::error::ErrorInformation;
use trustification_infrastructure::{app::http::HttpServerBuilder, MainContext};
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
                    .configure(sbom::configure(authenticator.clone()))
                    .configure(advisory::configure(authenticator.clone()))
                    .configure(crate::guac::configure(authenticator.clone()))
                    .configure(cve::configure(authenticator.clone()))
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("response error: {0} / {1}")]
    Response(StatusCode, String),
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("authentication error: {0}")]
    AuthClient(#[from] AuthClientError),
    #[error("guac error: {0}")]
    Guac(#[from] crate::guac::service::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::error::Error),
    #[error("collectorist error: {0}")]
    Collectorist(#[from] collectorist::Error),
    #[error("v11y error: {0}")]
    V11y(#[from] v11y::Error),
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());
        match self {
            Self::Response(status, error) => res.json(ErrorInformation {
                error: format!("{}", status),
                message: "Error response from backend service".to_string(),
                details: error.to_string(),
            }),
            Self::Request(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error creating request to backend service".to_string(),
                details: error.to_string(),
            }),
            Self::UrlParse(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error constructing url to backend service".to_string(),
                details: error.to_string(),
            }),
            Self::AuthClient(error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: "Error creating authentication client".to_string(),
                details: error.to_string(),
            }),
            Self::Serde(error) => res.json(ErrorInformation {
                error: "Serialization".to_string(),
                message: "Serialization error".to_string(),
                details: error.to_string(),
            }),
            Self::Guac(error) => res.json(ErrorInformation {
                error: "Guac".to_string(),
                message: "Error contacting GUAC".to_string(),
                details: error.to_string(),
            }),
            Self::Collectorist(error) => res.json(ErrorInformation {
                error: "collectorist".to_string(),
                message: "Error contacting collectorist".to_string(),
                details: error.to_string(),
            }),
            Self::V11y(error) => res.json(ErrorInformation {
                error: "v11y".to_string(),
                message: "Error contacting v11y".to_string(),
                details: error.to_string(),
            }),
        }
    }
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Response(status, _) => *status,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub struct AppState {
    client: reqwest::Client,
    pub provider: Arc<dyn TokenProvider>,
    pub bombastic: reqwest::Url,
    pub vexination: reqwest::Url,
}

impl AppState {
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
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            let status = response.status();
            match response.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }

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
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<bombastic_model::prelude::SearchResult>().await?)
        } else {
            let status = response.status();
            match response.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }

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
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.bytes_stream())
        } else {
            let status = response.status();
            match response.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }

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
            .inject_token(provider)
            .await?
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            Ok(response.json::<vexination_model::prelude::SearchResult>().await?)
        } else {
            let status = response.status();
            match response.text().await {
                Ok(body) => Err(Error::Response(status, body)),
                Err(e) => Err(Error::Request(e)),
            }
        }
    }
}
