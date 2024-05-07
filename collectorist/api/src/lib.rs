use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use actix_web::web;
use reqwest::Url;

use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{OpenIdTokenProviderConfigArguments, TokenProvider},
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustification_common::tls::ClientConfig;
use trustification_infrastructure::{
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::{self, Collectorist, Endpoint},
    health::checks::Probe,
    Infrastructure, InfrastructureConfig,
};

use crate::config::CollectorsConfig;
use crate::state::AppState;

mod config;
mod coordinator;
mod db;
pub mod server;
mod state;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        env,
        long = "csub-url",
        default_value_t = endpoint::GuacCollectSub::url()
    )]
    pub(crate) csub_url: Url,

    #[arg(env, long = "collector-config")]
    pub(crate) collector_config: Option<PathBuf>,

    /// Base path to the database store. Defaults to the local directory.
    #[arg(env, long = "storage-base")]
    pub(crate) storage_base: Option<PathBuf>,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub http: HttpServerConfig<Collectorist>,

    #[command(flatten)]
    pub client: ClientConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let (authn, authz) = self.auth.split(self.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.devmode, self.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        Infrastructure::from(self.infra)
            .run(
                "collectorist-api",
                |_context| async { Ok(()) },
                |context| async move {
                    let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                    let state = Self::configure(
                        self.client.build_client()?,
                        self.storage_base,
                        self.collector_config,
                        self.csub_url,
                        provider,
                        self.devmode,
                    )
                    .await?;

                    let (probe, check) = Probe::new("Not connected to CSUB");

                    context.health.readiness.register("connected.collectSub", check).await;

                    let server = {
                        let state = state.clone();
                        async move {
                            let http = HttpServerBuilder::try_from(self.http)?
                                .metrics(context.metrics.registry().clone(), "v11y_api")
                                .authorizer(authorizer.clone())
                                .configure(move |svc| {
                                    let authenticator = authenticator.clone();
                                    let swagger_oidc = swagger_oidc.clone();

                                    svc.app_data(web::Data::from(state.clone()))
                                        .configure(|cfg| server::config(cfg, authenticator, swagger_oidc));
                                });

                            http.run().await
                        }
                    };

                    let updater = state.coordinator.update(state.clone());
                    let listener = state.coordinator.listen(&state, probe);
                    tokio::select! {
                        _ = listener => { }
                        _ = server => { }
                        _ = updater => {}
                    }
                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure<P>(
        client: reqwest::Client,
        base: Option<PathBuf>,
        collector_config: Option<PathBuf>,
        csub_url: Url,
        provider: P,
        devmode: bool,
    ) -> anyhow::Result<Arc<AppState>>
    where
        P: TokenProvider + Clone + 'static,
    {
        let collectorist_config = collector_config.unwrap_or_else(|| "collectorist.yaml".into());

        let collectorist_config = if collectorist_config.exists() {
            serde_yaml::from_reader(File::open(collectorist_config)?)?
        } else if devmode {
            CollectorsConfig::devmode()
        } else {
            log::error!(
                "configuration file {} missing, no collectors configured",
                collectorist_config.to_str().unwrap_or("<unknown>")
            );

            CollectorsConfig {
                collectors: Default::default(),
            }
        };

        let base = base.unwrap_or_else(|| ".".into());
        let state = Arc::new(AppState::new(client, base, &collectorist_config, csub_url, provider).await?);
        Ok(state)
    }
}
