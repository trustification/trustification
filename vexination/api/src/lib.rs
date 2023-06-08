#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::{net::SocketAddr, path::PathBuf, process::ExitCode, str::FromStr, time::Duration};

use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    #[arg(long = "storage-endpoint", default_value = None)]
    pub(crate) storage_endpoint: Option<String>,

    #[command(flatten)]
    pub(crate) infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(|| async {
                let storage = trustification_storage::create("vexination", self.devmode, self.storage_endpoint)?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

                server::run(storage, addr).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
