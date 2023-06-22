use std::{
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    time::{Duration, SystemTime},
};

use url::{Position, Url};
use time::{Date, Month, UtcOffset};
use crate::bombastic::BombasticClient;
use crate::changes::ChangeTracker;
use crate::walker::run;

mod bombastic;
mod changes;
mod walker;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    /// SBOMs index URL
    #[arg(long)]
    pub(crate) sbom_source: Option<url::Url>,

    /// Bombastic host
    #[arg(long)]
    pub(crate) bombastic: url::Url,

    /// OpenPGP policy date.
    #[arg(long)]
    policy_date: Option<humantime::Timestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    v3_signatures: bool,

    /// Long-running mode. The index file will be scanned for changes every interval.
    #[arg(long = "scan-interval")]
    pub sync_interval: Option<humantime::Duration>,

}

const CHANGE_ADDRESS : &str = "https://access.redhat.com/security/data/sbom/beta/changes.csv";

//TODO a result enum ?
impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {

        let source = self.sbom_source.unwrap_or(Url::parse(CHANGE_ADDRESS).unwrap());

        let client = BombasticClient::new(self.bombastic);

        let validation_date: Option<SystemTime> = match (self.policy_date, self.v3_signatures) {
            (_, true) => Some(SystemTime::from(
                Date::from_calendar_date(2007, Month::January, 1)
                    .unwrap()
                    .midnight()
                    .assume_offset(UtcOffset::UTC),
            )),
            (Some(date), _) => Some(date.into()),
            _ => None,
        };

        //tracing::debug!("Policy date: {validation_date:?}");
        //let options = ValidationOptions { validation_date };

        let mut watcher = ChangeTracker::new(source.clone());

        let mut source = source;

        // remove the "change.csv" segment from the URL
        source.path_segments_mut().unwrap().pop();

        if let Some(sync_interval) = self.sync_interval {
            let mut interval = tokio::time::interval(sync_interval.into());
            loop {
                interval.tick().await;

                for entry in watcher.update().await? {

                    // craft the url to the SBOM file
                    source.path_segments_mut().unwrap().extend(entry.split("/"));

                    run(&client, &source).await.map_err(|e| {
                        // FIXME use a logger
                        println!("ERROR with {entry} : {e}. Skipping");
                        e
                    })?;

                    // cleanup the url for the next run
                    source.path_segments_mut().unwrap().pop().pop();
                }

            }

            //FIXME avoid the duplication
        } else {
            for entry in watcher.update().await? {

                // craft the url to the SBOM file
                source.path_segments_mut().unwrap().extend(entry.split("/"));

                run(&client, &source);

                // cleanup the url for the next run
                source.path_segments_mut().unwrap().pop().pop();
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
