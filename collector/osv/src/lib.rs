mod client;
mod server;

use crate::server::{deregister_with_collectorist, register_with_collectorist};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;
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

    #[arg(short = 'u', long = "collectorist-url", default_value = "http://localhost:9919/")]
    pub(crate) collectorist_url: String,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("collector-osv", |_metrics| async move {
                let state = Self::configure("osv".into(), self.collectorist_url).await?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
                let server = server::run(state.clone(), addr);
                let register = register_with_collectorist(state.clone());

                tokio::select! {
                     _ = server => { }
                     _ = register => { }
                }

                deregister_with_collectorist(state.clone()).await;
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(collector_id: String, collectorist_url: String) -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new(collector_id, collectorist_url));
        Ok(state)
    }
}

pub struct AppState {
    addr: RwLock<Option<SocketAddr>>,
    connected: AtomicBool,
    client: collectorist_client::Client,
    guac_url: RwLock<Option<String>>,
}

impl AppState {
    pub fn new(collector_id: String, collectorist_url: String) -> Self {
        Self {
            addr: RwLock::new(None),
            connected: AtomicBool::new(false),
            client: collectorist_client::Client::new(collector_id, collectorist_url),
            guac_url: RwLock::new(None),
        }
    }
}

pub(crate) type SharedState = Arc<AppState>;
