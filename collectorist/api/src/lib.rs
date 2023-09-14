use crate::state::AppState;
use reqwest::Url;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use trustification_auth::client::OpenIdTokenProviderConfigArguments;
use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustification_infrastructure::{
    endpoint::{self, Endpoint},
    endpoint::{Collectorist, EndpointServerConfig},
    Infrastructure, InfrastructureConfig,
};

mod coordinator;
mod db;
pub mod server;
mod state;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<Collectorist>,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        env,
        short = 'u',
        long = "csub-url",
        default_value_t = endpoint::GuacCollectSub::url()
    )]
    pub(crate) csub_url: Url,

    #[arg(
        env,
        short = 'g',
        long = "guac-url",
        default_value_t = endpoint::GuacGraphQl::url()
    )]
    pub(crate) guac_url: Url,

    /// Base path to the database store. Defaults to the local directory.
    #[arg(env, short = 'b', long = "storage-base")]
    pub(crate) storage_base: Option<PathBuf>,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        if self.devmode {
            self.guac_url = Url::parse("http://localhost:8085").unwrap();
            self.csub_url = Url::parse("http://localhost:8086").unwrap();
        }

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
            .run("collectorist-api", |context| async move {
                let state = Self::configure(self.storage_base, self.csub_url, self.guac_url).await?;
                let server = server::run(
                    state.clone(),
                    self.api.socket_addr()?,
                    context.metrics,
                    authenticator,
                    authorizer,
                    swagger_oidc,
                );
                let listener = state.coordinator.listen(&state);
                tokio::select! {
                     _ = listener => { }
                     _ = server => { }
                }
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(base: Option<PathBuf>, csub_url: Url, guac_url: Url) -> anyhow::Result<Arc<AppState>> {
        let base = base.unwrap_or_else(|| ".".into());
        let state = Arc::new(AppState::new(base, csub_url, guac_url).await?);
        Ok(state)
    }
}
