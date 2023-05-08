use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use bombastic_index::Index;
use bombastic_storage::{Config, Storage};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(short = 'i', long = "index")]
    pub(crate) index: PathBuf,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) sync_interval_seconds: u64,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index = Index::new(&self.index)?;
        let storage = Storage::new(Config::new_minio_test())?;
        let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
        let interval = Duration::from_secs(self.sync_interval_seconds);

        server::run(storage, index, addr, interval).await?;
        Ok(ExitCode::SUCCESS)
    }
}
