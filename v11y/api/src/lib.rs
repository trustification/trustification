use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use trustification_auth::auth::AuthConfigArguments;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig};

use trustification_infrastructure::endpoint::{EndpointServerConfig, V11y};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

use crate::db::Db;

mod db;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<V11y>,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    /// Base path to the database store. Defaults to the local directory.
    #[arg(env, long = "storage-base")]
    pub(crate) storage_base: Option<PathBuf>,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

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
            .run(
                "v11y",
                |_context| async { Ok(()) },
                |context| async move {
                    let state = Self::configure(self.storage_base).await?;
                    let addr = SocketAddr::from_str(&format!("{}:{}", self.api.bind, self.api.port))?;
                    let server = server::run(
                        state.clone(),
                        addr,
                        context.metrics,
                        authenticator,
                        authorizer,
                        swagger_oidc,
                    );

                    server.await?;
                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(base: Option<PathBuf>) -> anyhow::Result<Arc<AppState>> {
        let base = base.unwrap_or_else(|| ".".into());
        let state = Arc::new(AppState::new(base).await?);
        Ok(state)
    }
}

#[allow(unused)]
pub struct AppState {
    db: Db,
}

impl AppState {
    pub async fn new(base: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        Ok(Self {
            db: Db::new(base).await?,
        })
    }
}
