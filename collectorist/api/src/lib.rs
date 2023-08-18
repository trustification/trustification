use reqwest::Url;
use std::process::ExitCode;
use std::sync::Arc;

use trustification_infrastructure::endpoint::{Collectorist, EndpointServerConfig};
use trustification_infrastructure::{
    endpoint::{self, Endpoint},
    Infrastructure, InfrastructureConfig,
};

use crate::state::AppState;

mod coordinator;
mod db;
pub mod server;
mod state;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<Collectorist>,

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
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("collectorist-api", |_metrics| async move {
                let state = Self::configure(self.csub_url, self.guac_url).await?;
                let server = server::run(state.clone(), self.api.socket_addr()?);
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
