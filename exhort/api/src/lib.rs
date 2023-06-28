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

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        let state = self.configure()?;
        Infrastructure::from(self.infra)
            .run("exhort-api", || async move {
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

                server::run(state, addr).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    fn configure(&mut self) -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState {});

        Ok(state)
    }
}

pub struct AppState {}

pub(crate) type SharedState = Arc<AppState>;
