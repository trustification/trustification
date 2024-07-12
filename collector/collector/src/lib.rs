use std::process::ExitCode;

/// Run collector services (`trust collector --help` for details)
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Osv(collector_osv::Run),
    Snyk(collector_snyk::Run),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Osv(run) => run.run().await,
            Self::Snyk(run) => run.run().await,
        }
    }
}
