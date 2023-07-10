#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
use std::{
    path::PathBuf,
    process::ExitCode,
    str::FromStr,
    time::{Duration, SystemTime},
};

use csaf_walker::validation::ValidationOptions;
use prometheus::Registry;
use time::{Date, Month, UtcOffset};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    /// Source URL
    #[arg(short, long)]
    pub(crate) source: url::Url,

    /// OpenPGP policy date.
    #[arg(long)]
    policy_date: Option<humantime::Timestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    v3_signatures: bool,

    #[arg(long = "devmode", default_value_t = false)]
    pub(crate) devmode: bool,

    /// Number of workers, too many might get you rate-limited
    #[arg(short, long, default_value = "1")]
    pub(crate) workers: usize,

    #[command(flatten)]
    pub(crate) storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("vexination-walker", |metrics| async move {
                let storage = self.storage.create("vexination", self.devmode, metrics.registry())?;
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

                log::debug!("Policy date: {validation_date:?}");

                let options = ValidationOptions { validation_date };

                server::run(self.workers, storage, self.source, options).await
            })
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
