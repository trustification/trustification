use std::process::ExitCode;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Api(bombastic_api::Run),
    Indexer(bombastic_indexer::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Api(run) => run.run().await,
            Self::Indexer(run) => run.run().await,
        }
    }
}
