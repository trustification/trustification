use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{ExitCode, Termination};

use clap::Parser;

#[allow(clippy::large_enum_variant)]
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

    #[command(subcommand)]
    V11y(v11y::Command),

    Exporter(exporter::Run),

    #[command(subcommand)]
    Admin(trustification_admin::Command),
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
            Command::V11y(run) => run.run().await,
            Command::Admin(run) => run.run().await,
        }
    }
}

#[tokio::main]
async fn main() -> impl Termination {
    load_xdg_config();
    Cli::parse().run().await
}

fn load_xdg_config() {
    let config_dir = if let Ok(xdg_config_home) = std::env::var("XDG_CONFIG_HOME") {
        Some(Path::new(&xdg_config_home).join("trustification"))
    } else if let Ok(home) = std::env::var("HOME") {
        Some(Path::new(&home).join(".config").join("trustification"))
    } else {
        None
    };

    if let Some(config_dir) = config_dir {
        if config_dir.exists() && config_dir.is_dir() {
            if let Ok(dir) = config_dir.read_dir() {
                for entry in dir.flatten() {
                    let var_name = entry.file_name().to_str().unwrap().to_string();
                    if let Ok(mut file) = File::open(entry.path()) {
                        let mut var_value = String::new();
                        if file.read_to_string(&mut var_value).is_ok() {
                            std::env::set_var(var_name, var_value.trim());
                        }
                    }
                }
            } else {
                eprintln!("Warning: unable to read configuration directory: {:?}", config_dir);
            }
        }
    }
}
