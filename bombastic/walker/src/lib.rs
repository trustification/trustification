use crate::scanner::{Options, Scanner};
use clap::{arg, command, Args};
use std::process::ExitCode;
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use url::Url;

mod scanner;

#[derive(Args, Debug)]
#[command(
    about = "Run the SBOM walker",
    args_conflicts_with_subcommands = true,
    rename_all_env = "SCREAMING_SNAKE_CASE"
)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    /// Long-running mode. The index file will be scanned for changes every interval.
    #[arg(long = "scan-interval")]
    pub scan_interval: Option<humantime::Duration>,

    /// GPG key used to sign SBOMs
    #[arg(long = "signing-key-source")]
    pub signing_key_source: Option<Url>,

    /// Bombastic host
    #[arg(long = "bombastic-url")]
    pub bombastic: Url,

    /// SBOMs index URL
    #[arg(long = "changes-url")]
    pub index_source: Option<Url>,

    /// OIDC client
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct WalkerConfig {}

const CHANGE_ADDRESS: &str = "https://access.redhat.com/security/data/sbom/beta/changes.csv";

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "bombastic-walker",
                |_context| async { Ok(()) },
                |_| async move {
                    let provider = self.oidc.clone().into_provider_or_devmode(self.devmode).await?;

                    let source = self.index_source.clone().unwrap_or(Url::parse(CHANGE_ADDRESS).unwrap());
                    let scanner = Scanner::new(Options {
                        source,
                        key: self.signing_key_source.as_ref(),
                    });

                    if let Some(sync_interval) = self.scan_interval {
                        scanner.run().await?;
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
