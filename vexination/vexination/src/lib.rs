use std::process::ExitCode;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Walker(vexination_walker::Run),
    Indexer(vexination_indexer::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Walker(run) => run.run().await,
            Self::Indexer(run) => run.run().await,
        }
    }
}
