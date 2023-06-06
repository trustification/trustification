#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use trustification_index::IndexStore;
use vexination_index::Index;

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

    #[arg(short = 'i', long = "index")]
    pub(crate) index: Option<PathBuf>,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) index_sync_interval_seconds: u64,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index_dir: PathBuf = self.index.unwrap_or_else(|| {
            use rand::RngCore;
            let r = rand::thread_rng().next_u32();
            std::env::temp_dir().join(format!("vexination-index.{}", r))
        });

        std::fs::create_dir(&index_dir)?;

        let index = IndexStore::new(&index_dir, Index::new())?;
        let storage = trustification_storage::create("vexination", self.devmode, self.storage_endpoint)?;
        let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

        server::run(
            storage,
            index,
            addr,
            Duration::from_secs(self.index_sync_interval_seconds),
        )
        .await?;
        Ok(ExitCode::SUCCESS)
    }
}
