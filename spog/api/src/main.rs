use std::process::{ExitCode, Termination};

use clap::Parser;

mod guac;
mod index;
mod package;
mod sbom;
mod server;
mod snyk;
mod vulnerability;

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
            Command::Run(Run {
                bind,
                port,
                guac_url,
                snyk,
            }) => {
                let s = server::Server::new(bind, port, guac_url, snyk);
                s.run().await?;
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub(crate) snyk: Snyk,

    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub(crate) guac_url: String,
}

#[derive(clap::Args, Debug, Clone)]
#[group(required = false)]
pub struct Snyk {
    #[arg(long = "snyk-org")]
    pub(crate) org: Option<String>,

    #[arg(long = "snyk-token")]
    pub(crate) token: Option<String>,
}

#[tokio::main]
async fn main() -> impl Termination {
    env_logger::init();
    Cli::parse().run().await
}
