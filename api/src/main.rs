use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bombastic_index::Index;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use std::{
    process::{ExitCode, Termination},
    str::FromStr,
};

mod server;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Run(Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Trusted Content API Server",
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
            Command::Run(Run { index, bind, port }) => {
                let addr = SocketAddr::from_str(&format!("{}:{}", bind, port))?;
                server::run(index, addr).await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(short = 'i', long = "index")]
    pub(crate) index: PathBuf,
}

#[tokio::main]
async fn main() -> impl Termination {
    //env_logger::init();
    tracing_subscriber::fmt::init();
    Cli::parse().run().await
}
