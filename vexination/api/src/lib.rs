#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use trustification_storage::{Config, Storage};

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
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let storage = if self.devmode {
            Storage::new(Config::test("vexination"), trustification_storage::StorageType::Minio)?
        } else {
            Storage::new(Config::defaults("vexination")?, trustification_storage::StorageType::S3)?
        };
        let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

        server::run(storage, addr).await?;
        Ok(ExitCode::SUCCESS)
    }
}
