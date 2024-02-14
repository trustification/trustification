use crate::scanner::{Options, Scanner};
use anyhow::anyhow;
use clap::{arg, command, Args};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;
use trustification_auth::client::{OpenIdTokenProviderConfig, OpenIdTokenProviderConfigArguments};
use trustification_infrastructure::{
    endpoint::{self, Endpoint},
    Infrastructure, InfrastructureConfig,
};
use url::Url;
use walker_common::sender::provider::TokenProvider;

mod scanner;

const DEVMODE_SOURCE: &str = "https://www.redhat.com/.well-known/csaf/provider-metadata.json";

#[derive(Args, Debug)]
#[command(
    about = "Run the VEX walker",
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

    /// OpenPGP policy date.
    #[arg(long)]
    pub policy_date: Option<humantime::Timestamp>,

    /// Bombastic
    #[arg(long = "sink", env, default_value_t = endpoint::Bombastic::url())]
    pub sink: Url,

    /// VEX source URL or path
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
    pub retry_delay: Option<humantime::Duration>,

    /// Additional root certificates for the destination
    #[arg(long = "sender-root-certificates")]
    pub additional_root_certificates: Vec<PathBuf>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "vexination-walker",
                |_context| async { Ok(()) },
                |_| async move {
                    let source = self
                        .source
                        .or_else(|| self.devmode.then(|| DEVMODE_SOURCE.to_string()))
                        .ok_or_else(|| anyhow!("Missing source. Provider either --source <url> or --devmode"))?;

                    let validation_date: Option<SystemTime> = self.policy_date.map(|d| d.into());

                    log::debug!("Policy date: {validation_date:?}");

                    let provider = match OpenIdTokenProviderConfig::from_args_or_devmode(self.oidc, self.devmode) {
                        Some(OpenIdTokenProviderConfig {
                            issuer_url,
                            client_id,
                            client_secret,
                            refresh_before,
                            tls_insecure: insecure_tls,
                        }) => {
                            let config = walker_common::sender::provider::OpenIdTokenProviderConfig {
                                issuer_url,
                                client_id,
                                client_secret,
                                refresh_before,
                                tls_insecure: insecure_tls,
                            };
                            Arc::new(walker_common::sender::provider::OpenIdTokenProvider::with_config(config).await?)
                                as Arc<dyn TokenProvider>
                        }
                        None => Arc::new(()),
                    };

                    let scanner = Scanner::new(Options {
                        source,
                        target: self.sink.join("/api/v1/vex")?,
                        provider,
                        validation_date,
                        since_file: self.since_file,
                        retries: self.retries,
                        retry_delay: self.retry_delay.map(|d| d.into()),
                        additional_root_certificates: self.additional_root_certificates,
                    });

                    if let Some(interval) = self.scan_interval {
                        scanner.run(interval.into()).await?;
                    } else {
                        scanner.run_once().await?;
                    }

                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
