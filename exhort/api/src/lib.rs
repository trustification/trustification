use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod component_analysis;
mod package_manager;
mod request;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 9919)]
    pub port: u16,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let infra = Infrastructure::from(self.infra).run("exhort-api", |_metrics| async move {
            let state = Self::configure()?;
            let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

            server::run(state, addr).await
        });

        infra.await?;

        Ok(ExitCode::SUCCESS)
    }

    fn configure() -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState {});

        Ok(state)
    }
}

pub struct AppState {}

pub(crate) type SharedState = Arc<AppState>;
