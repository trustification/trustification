use clap::{Parser, Subcommand};

mod common;
mod config;
mod errors;
mod task;

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::Test(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Test(task::Test),
}

fn main() -> anyhow::Result<()> {
    Cli::parse().run()
}
