use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use std::str::FromStr;

use bombastic_index::Index;
use clap::Parser;
use serde::{Deserialize, Serialize};

mod indexer;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Run(Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Bombastic Indexer",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    async fn run(self) -> ExitCode {
        match self.run_command().await {
            Ok(code) => code,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Run(Run { index }) => {
                indexer::run(index).await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the indexer", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short = 'i', long = "index")]
    pub(crate) index: PathBuf,
}

#[tokio::main]
async fn main() -> impl Termination {
    //env_logger::init();
    tracing_subscriber::fmt::init();
    Cli::parse().run().await
}
