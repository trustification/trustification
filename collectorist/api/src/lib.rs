use crate::state::AppState;
use reqwest::Url;
use std::process::ExitCode;
use std::sync::Arc;
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

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,
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
            .run("collectorist-api", |metrics| async move {
                let state = Self::configure(self.csub_url, self.guac_url).await?;
                let server = server::run(
                    state.clone(),
                    self.api.socket_addr()?,
                    metrics,
                    authenticator,
                    authorizer,
                    swagger_oidc,
                );
                let listener = state.coordinator.listen(state.clone());
                tokio::select! {
                     _ = listener => { }
                     _ = server => { }
                }
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(csub_url: Url, guac_url: Url) -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new(csub_url, guac_url).await?);
        Ok(state)
    }
}

pub(crate) type SharedState = Arc<AppState>;
