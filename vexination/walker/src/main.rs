use std::process::{ExitCode, Termination};

use clap::Parser;
use vexination_walker::Run;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Run(Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Vexination Walker",
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
            Command::Run(cmd) => cmd.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    //env_logger::init();
    tracing_subscriber::fmt::init();
    Cli::parse().run().await
}
