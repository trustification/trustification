use std::process::ExitCode;
use std::{net::TcpListener, path::PathBuf};
use trustification_auth::authenticator::config::AuthenticatorConfig;

use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod advisory;
//mod guac;
//mod snyk;
mod index;
//mod package;
mod analyze;
mod config;
mod sbom;
mod search;
mod server;
// mod vulnerability;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub snyk: Snyk,

    /// Enable developer mode
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub port: u16,

    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub guac_url: String,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub sync_interval_seconds: u64,

    #[arg(long = "bombastic-url", default_value = "http://localhost:8082")]
    pub bombastic_url: reqwest::Url,

    #[arg(long = "vexination-url", default_value = "http://localhost:8081")]
    pub vexination_url: reqwest::Url,

    #[arg(long = "crda-url", default_value = "http://localhost:8081")]
    pub crda_url: Option<reqwest::Url>,

    /// Path to the UI configuration file, overriding the default configuration file.
    #[arg(short, long = "config", env = "SPOG_UI_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub oidc: AuthenticatorConfig,
}

impl Run {
    pub async fn run(self, listener: Option<TcpListener>) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra.clone())
            .run("spog-api", |metrics| async move {
                let s = server::Server::new(self);
                s.run(metrics.registry(), listener).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug, Clone, Default)]
#[group(required = false)]
pub struct Snyk {
    #[arg(long = "snyk-org")]
    pub(crate) org: Option<String>,

    #[arg(long = "snyk-token")]
    pub(crate) token: Option<String>,
}
