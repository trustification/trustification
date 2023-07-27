use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

use crate::state::AppState;

mod db;
mod gatherer;
pub mod server;
mod state;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 9919)]
    pub port: u16,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(short = 'u', long = "csub-url", default_value = "http://localhost:2782/")]
    pub(crate) csub_url: String,

    #[arg(short = 'g', long = "guac-url", default_value = "http://localhost:8080/query")]
    pub(crate) guac_url: String,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("collectorist-api", |_metrics| async move {
                let state = Self::configure(self.csub_url, self.guac_url).await?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
                let server = server::run(state.clone(), addr);
                let listener = state.gatherer.listen(state.clone());
                tokio::select! {
                     _ = listener => { }
                     _ = server => { }
                }
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(csub_url: String, guac_url: String) -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new(csub_url, guac_url).await?);
        Ok(state)
    }
}

pub(crate) type SharedState = Arc<AppState>;
