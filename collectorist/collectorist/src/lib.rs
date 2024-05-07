use std::process::ExitCode;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Api(collectorist_api::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Api(run) => run.run().await,
        }
    }
}
