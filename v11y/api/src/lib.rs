mod server;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 0)]
    pub port: u16,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("v11y", |_metrics| async move {
                let state = Self::configure().await?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
                let server = server::run(state.clone(), addr);

                server.await?;
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure() -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new());
        Ok(state)
    }
}

pub struct AppState {}

impl AppState {
    pub fn new() -> Self {
        Self {}
    }
}

pub(crate) type SharedState = Arc<AppState>;
