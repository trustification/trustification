use std::process::ExitCode;

mod reindex;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Reindex(reindex::Reindex),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Reindex(reindex) => reindex.run().await,
        }
    }
}
