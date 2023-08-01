use std::process::ExitCode;

/// Single Pane of Glass
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Api(spog_api::Run),
    //Search(spog_search::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Api(run) => run.run(None).await,
            // Self::Search(run) => run.run().await,
        }
    }
}
