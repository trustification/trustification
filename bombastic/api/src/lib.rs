use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use trustification_index::Index;
use trustification_storage::{Config, Storage};

mod sbom;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(short = 'i', long = "index")]
    pub(crate) index: Option<PathBuf>,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) sync_interval_seconds: u64,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index: PathBuf = self.index.unwrap_or_else(|| {
            use rand::RngCore;
            let r = rand::thread_rng().next_u32();
            std::env::temp_dir().join(format!("bombastic-api.{}.sqlite", r))
        });
        let index = Index::new(&index)?;
        let storage = if self.devmode {
            Storage::new(Config::test("bombastic"), trustification_storage::StorageType::Minio)?
        } else {
            Storage::new(Config::defaults("bombastic")?, trustification_storage::StorageType::S3)?
        };
        let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
        let interval = Duration::from_secs(self.sync_interval_seconds);

        server::run(storage, index, addr, interval).await?;
        Ok(ExitCode::SUCCESS)
    }
}
