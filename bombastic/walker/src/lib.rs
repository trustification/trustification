use std::process::ExitCode;

use crate::changes::ChangeTracker;
use crate::shell_wrap::ScriptContext;
use clap::{arg, command, Args};
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use url::Url;

mod changes;
mod shell_wrap;

#[derive(Args, Debug)]
#[command(about = "Run the SBOM walker", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub(crate) config: WalkerConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct WalkerConfig {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub script_context: ScriptContext,

    /// Long-running mode. The index file will be scanned for changes every interval.
    #[arg(long = "scan-interval")]
    pub scan_interval: Option<humantime::Duration>,

    /// GPG key used to sign SBOMs
    #[arg(long = "signing-key-source")]
    pub(crate) signing_key_source: Option<Url>,

    /// Bombastic host
    #[arg(long = "bombastic-url")]
    pub(crate) bombastic: Url,

    /// SBOMs index URL
    #[arg(long = "changes-url")]
    pub(crate) index_source: Option<Url>,

    /// OIDC client
    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,
}

const CHANGE_ADDRESS: &str = "https://access.redhat.com/security/data/sbom/beta/changes.csv";

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "bombastic-walker",
                |_context| async { Ok(()) },
                |_| async move {
                    let provider = self
                        .config
                        .oidc
                        .clone()
                        .into_provider_or_devmode(self.config.devmode)
                        .await?;

                    let source = self
                        .config
                        .index_source
                        .clone()
                        .unwrap_or(Url::parse(CHANGE_ADDRESS).unwrap());
                    let mut watcher = ChangeTracker::new(source.clone());

                    // remove the "change.csv" segment from the URL
                    let mut source = source;
                    source.path_segments_mut().unwrap().pop();

                    // add ProdSec signing key to trusted gpg keys
                    self.config
                        .script_context
                        .setup_gpg(self.config.signing_key_source.as_ref())?;

                    if let Some(sync_interval) = self.config.scan_interval {
                        let mut interval = tokio::time::interval(sync_interval.into());
                        loop {
                            interval.tick().await;

                            Self::call_script(&self.config, &provider, watcher.update().await?, &source).await?;
                        }
                    } else {
                        Self::call_script(&self.config, &provider, watcher.update().await?, &source).await?;
                    }
                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn call_script<TP: TokenProvider>(
        config: &WalkerConfig,
        provider: &TP,
        entries: Vec<String>,
        sbom_path: &Url,
    ) -> anyhow::Result<()> {
        for entry in entries {
            let mut sbom_path = sbom_path.clone();
            // craft the url to the SBOM file
            sbom_path.path_segments_mut().unwrap().extend(entry.split('/'));

            let access_token = provider.provide_access_token().await?;

            config
                .script_context
                .bombastic_upload(&sbom_path, &config.bombastic, access_token);

            // cleanup the url for the next run
            sbom_path.path_segments_mut().unwrap().pop().pop();
        }

        Ok(())
    }
}
