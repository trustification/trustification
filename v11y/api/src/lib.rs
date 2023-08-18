use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

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

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("v11y", |_metrics| async move {
                let state = Self::configure().await?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.api.bind, self.api.port))?;
                let server = server::run(state.clone(), addr);

                server.await?;
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure() -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new().await?);
        Ok(state)
    }
}

#[allow(unused)]
pub struct AppState {
    db: Db,
}

impl AppState {
    pub async fn new() -> Result<Self, anyhow::Error> {
        Ok(Self { db: Db::new().await? })
    }
}

pub(crate) type SharedState = Arc<AppState>;
