use std::{path::PathBuf, process::ExitCode, time::SystemTime};

use time::{Date, Month, UtcOffset};
use trustification_auth::client::OpenIdTokenProviderConfigArguments;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use url::Url;
use walker_common::validate::ValidationOptions;

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    /// Source URL or path
    #[arg(short, long)]
    pub(crate) source: String,

    /// Vexination upload url
    #[arg(short = 'S', long)]
    pub(crate) sink: Url,

    /// Distributions to ignore
    #[arg(long, default_value = "Vec::new()")]
    ignore_distributions: Vec<Url>,

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
    pub infra: InfrastructureConfig,

    /// OIDC client
    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,

    /// A file to read/store the last sync timestamp to at the end of a successful run.
    #[arg(long = "since-file")]
    pub since_file: Option<PathBuf>,

    /// Additional root certificates for the destination
    #[arg(long = "sender-root-certificates")]
    pub additional_root_certificates: Vec<PathBuf>,

    /// Only upload if a document's name has any of these prefixes.
    #[arg(long = "require-prefix")]
    pub required_prefixes: Vec<String>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "vexination-walker",
                |_context| async { Ok(()) },
                |_context| async move {
                    let provider = self.oidc.clone().into_provider_or_devmode(self.devmode).await?;

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

                    server::run(
                        self.workers,
                        self.source,
                        self.sink,
                        provider,
                        options,
                        self.ignore_distributions,
                        self.since_file,
                        self.additional_root_certificates,
                        self.required_prefixes,
                    )
                    .await
                },
            )
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
