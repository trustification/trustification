use crate::scanner::{Options, Scanner};
use anyhow::{anyhow, Context};
use clap::{arg, command, ArgAction, Args};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use trustification_auth::client::{OpenIdTokenProviderConfig, OpenIdTokenProviderConfigArguments};
use trustification_common_walker::report::{handle_report, ReportGenerateOption, SplitScannerError};
use trustification_infrastructure::{
    endpoint::{self, Endpoint},
    Infrastructure, InfrastructureConfig,
};
use url::Url;
use walker_common::sender::provider::TokenProvider;

mod processing;
mod report;
mod scanner;

const DEVMODE_SOURCE: &str = "https://access.redhat.com/security/data/sbom/beta/";
const DEVMODE_KEY: &str =
    "https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4";

#[derive(Args, Debug)]
#[command(
    about = "Run the SBOM walker",
    args_conflicts_with_subcommands = true,
    rename_all_env = "SCREAMING_SNAKE_CASE"
)]
pub struct Run {
    /// Apply reasonable settings for local development. Do not use in production!
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    /// Long-running mode. The index file will be scanned for changes every interval.
    #[arg(long = "scan-interval")]
    pub scan_interval: Option<humantime::Duration>,

    /// GPG key used to sign SBOMs, use the fragment of the URL as fingerprint.
    #[arg(long = "signing-key", env)]
    pub signing_key: Vec<Url>,

    /// OpenPGP policy date.
    #[arg(long)]
    pub policy_date: Option<humantime::Timestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    pub v3_signatures: bool,

    /// Allowing fixing invalid SPDX license expressions by setting them to NOASSERTION.
    #[arg(long, env, default_value_t = true, action = ArgAction::Set)]
    pub fix_licenses: bool,

    /// Bombastic
    #[arg(long = "sink", env, default_value_t = endpoint::Bombastic::url())]
    pub sink: Url,

    /// SBOMs source URL or path
    #[arg(long, env)]
    pub source: Option<String>,

    /// OIDC client
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    /// A file to read/store the last sync timestamp to at the end of a successful run.
    #[arg(long = "since-file")]
    pub since_file: Option<PathBuf>,

    /// Retry sending a file
    #[arg(long = "retries", default_value_t = 5)]
    pub retries: usize,

    /// Retry delay
    #[arg(long = "retry-delay")]
    pub retry_delay: Option<humantime::Duration>,

    /// Additional root certificates for the destination
    #[arg(long = "sender-root-certificates")]
    pub additional_root_certificates: Vec<PathBuf>,

    /// Allow logging of uploaded sbom file reports.
    #[arg(long, env, default_value_t = false, action = ArgAction::Set)]
    pub report_enable: bool,

    /// Define report output path
    #[arg(long, env, default_value = "/tmp/share/reports")]
    pub report_path: String,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "bombastic-walker",
                |_context| async { Ok(()) },
                |_| async move {
                    let source = self
                        .source
                        .or_else(|| self.devmode.then(|| DEVMODE_SOURCE.to_string()))
                        .ok_or_else(|| anyhow!("Missing source. Provider either --source <url> or --devmode"))?;

                    let keys = self
                        .signing_key
                        .into_iter()
                        .chain(
                            self.devmode
                                .then(|| Url::parse(DEVMODE_KEY).context("failed to parse devmode key"))
                                .transpose()?,
                        )
                        .map(|key| key.into())
                        .collect();

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
                        source,
                        target: self.sink.join("/api/v1/sbom")?,
                        keys,
                        provider,
                        validation_date,
                        fix_licenses: self.fix_licenses,
                        since_file: self.since_file,
                        retries: self.retries,
                        retry_delay: self.retry_delay.map(|d| d.into()),
                        additional_root_certificates: self.additional_root_certificates,
                    });

                    if let Some(interval) = self.scan_interval {
                        scanner.run(interval.into()).await?;
                    } else {
                        let (report, result) = scanner.run_once().await.split()?;
                        if self.report_enable {
                            handle_report(
                                report,
                                ReportGenerateOption {
                                    report_type: "SBOM".to_string(),
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
