use std::process::ExitCode;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Api(v11y_api::Run),
    Indexer(v11y_indexer::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Api(run) => run.run().await,
            Self::Indexer(run) => run.run().await,
        }
    }
}
