use crate::scanner::{Options, Scanner};
use clap::ArgAction;
use std::{path::PathBuf, process::ExitCode, sync::Arc, time::SystemTime};
use time::{Date, Month, UtcOffset};
use trustification_auth::client::{OpenIdTokenProviderConfig, OpenIdTokenProviderConfigArguments};
use trustification_common_walker::report::{handle_report, ReportGenerateOption, SplitScannerError};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use url::Url;
use walker_common::sender::provider::TokenProvider;

mod report;
mod scanner;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    /// Source URL or path
    #[arg(short, long)]
    pub source: String,

    /// Vexination upload url
    #[arg(short = 'S', long)]
    pub sink: Url,

    /// Distributions to ignore
    #[arg(long, default_value = "Vec::new()")]
    pub ignore_distributions: Vec<String>,

    /// OpenPGP policy date.
    #[arg(long)]
    pub policy_date: Option<humantime::Timestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    pub v3_signatures: bool,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    /// OIDC client
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    /// A file to read/store the last sync timestamp to at the end of a successful run.
    #[arg(long = "since-file")]
    pub since_file: Option<PathBuf>,

    /// Additional root certificates for the destination
    #[arg(long = "sender-root-certificates")]
    pub additional_root_certificates: Vec<PathBuf>,

    /// Only upload if a document's name has any of these prefixes.
    #[arg(long = "require-prefix")]
    pub required_prefixes: Vec<String>,

    /// Retry sending a file
    #[arg(long = "retries", default_value_t = 5)]
    pub retries: usize,

    /// Retry delay
    #[arg(long = "retry-delay")]
    pub retry_delay: Option<humantime::Duration>,

    /// Long-running mode. The index file will be scanned for changes every interval.
    #[arg(long = "scan-interval")]
    pub scan_interval: Option<humantime::Duration>,

    /// Allow logging of uploaded vexination file reports.
    #[arg(long, env, default_value_t = true, action = ArgAction::Set)]
    pub report_enable: bool,

    /// Define report output path
    #[arg(long, env, default_value = "/tmp/share/reports")]
    pub report_path: String,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "vexination-walker",
                |_context| async { Ok(()) },
                |_| async move {
                    let validation_date: Option<SystemTime> = match (self.policy_date, self.v3_signatures) {
                        (_, true) => Some(SystemTime::from(
                            Date::from_calendar_date(2007, Month::January, 1)
                                .expect("known calendar date must parse")
                                .midnight()
                                .assume_offset(UtcOffset::UTC),
                        )),
                        (Some(date), _) => Some(date.into()),
                        _ => None,
                    };

                    log::debug!("Policy date: {validation_date:?}");

                    let provider = match OpenIdTokenProviderConfig::from_args_or_devmode(self.oidc, self.devmode) {
                        Some(OpenIdTokenProviderConfig {
                            issuer_url,
                            client_id,
                            client_secret,
                            refresh_before,
                            tls_insecure,
                            tls_ca_certificates,
                        }) => {
                            let config = walker_common::sender::provider::OpenIdTokenProviderConfig {
                                issuer_url,
                                client_id,
                                client_secret,
                                refresh_before,
                                tls_insecure,
                                tls_ca_certificates,
                            };
                            Arc::new(walker_common::sender::provider::OpenIdTokenProvider::with_config(config).await?)
                                as Arc<dyn TokenProvider>
                        }
                        None => Arc::new(()),
                    };

                    let scanner = Scanner::new(Options {
                        source: self.source,
                        target: self.sink.join("/api/v1/vex")?,
                        provider,
                        validation_date,
                        since_file: self.since_file,
                        additional_root_certificates: self.additional_root_certificates,
                        required_prefixes: self.required_prefixes,
                        retries: self.retries,
                        retry_delay: self.retry_delay.map(|d| d.into()),
                        ignore_distributions: self.ignore_distributions,
                    });

                    if let Some(interval) = self.scan_interval {
                        scanner.run(interval.into()).await?;
                    } else {
                        let (report, result) = scanner.run_once().await.split()?;
                        if self.report_enable {
                            handle_report(
                                report,
                                ReportGenerateOption {
                                    report_type: "Vexination".to_string(),
                                    report_out_path: self.report_path,
                                },
                            )
                            .await?;
                        }
                        result?;
                    }

                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
