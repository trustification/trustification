use std::process::{ExitCode, Termination};

use clap::Parser;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Vexination(vexination::Command),
    #[command(subcommand)]
    Bombastic(bombastic::Command),
    #[command(subcommand)]
    Spog(spog::Command),
    #[command(subcommand)]
    Exhort(exhort::Command),
    #[command(subcommand)]
    Collectorist(collectorist::Command),

    #[command(subcommand)]
    Collector(collector::Command),

    Exporter(exporter::Run),
}

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version = env!("CARGO_PKG_VERSION"),
    about = "Trust",
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
                eprintln!("Error: {err}");
                for (n, err) in err.chain().skip(1).enumerate() {
                    if n == 0 {
                        eprintln!("Caused by:");
                    }
                    eprintln!("\t{err}");
                }

                ExitCode::FAILURE
            }
        }
    }

    async fn run_command(self) -> anyhow::Result<ExitCode> {
        match self.command {
            Command::Vexination(run) => run.run().await,
            Command::Bombastic(run) => run.run().await,
            Command::Spog(run) => run.run().await,
            Command::Exhort(run) => run.run().await,
            Command::Collectorist(run) => run.run().await,
            Command::Collector(run) => run.run().await,
            Command::Exporter(run) => run.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    Cli::parse().run().await
}
