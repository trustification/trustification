use std::process::ExitCode;

use crate::changes::ChangeTracker;
use crate::shell_wrap::{run, script_path, setup_gpg};
use clap::{arg, command, Args};
use url::Url;

mod changes;
mod shell_wrap;

#[derive(Args, Debug)]
#[command(about = "Run the SBOM walker", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub(crate) config: WalkerConfig,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct WalkerConfig {
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
}

const CHANGE_ADDRESS: &str = "https://access.redhat.com/security/data/sbom/beta/changes.csv";

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
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
        setup_gpg(self.config.signing_key_source.as_ref())?;

        // find the script location
        let script_path = script_path("walker.sh")?;

        if let Some(sync_interval) = self.config.scan_interval {
            let mut interval = tokio::time::interval(sync_interval.into());
            loop {
                interval.tick().await;

                self.call_script(watcher.update().await?, script_path.as_str(), &source);
            }
        } else {
            self.call_script(watcher.update().await?, script_path.as_str(), &source);
        }

        Ok(ExitCode::SUCCESS)
    }

    fn call_script(&self, entries: Vec<String>, script_path: &str, sbom_path: &Url) {
        for entry in entries {
            let mut sbom_path = sbom_path.clone();
            // craft the url to the SBOM file
            sbom_path.path_segments_mut().unwrap().extend(entry.split("/"));

            run(script_path, &sbom_path, &self.config.bombastic);

            // cleanup the url for the next run
            sbom_path.path_segments_mut().unwrap().pop().pop();
        }
    }
}
