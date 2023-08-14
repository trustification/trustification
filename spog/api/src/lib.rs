use std::process::ExitCode;
use std::{net::TcpListener, path::PathBuf};
use trustification_auth::authenticator::config::AuthenticatorConfig;
use trustification_auth::swagger_ui::SwaggerUiOidcConfig;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod advisory;
mod analyze;
mod config;
mod index;
mod sbom;
mod search;
mod server;

pub const DEFAULT_CRDA_PAYLOAD_LIMIT: usize = 10 * 1024 * 1024;

/// Run the API server
#[derive(clap::Args, Debug)]
#[command(
    about = "Run the api server",
    args_conflicts_with_subcommands = true,
    rename_all_env = "SCREAMING_SNAKE_CASE"
)]
pub struct Run {
    #[command(flatten)]
    pub snyk: Snyk,

    /// Enable developer mode
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(short, long, env, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", env, default_value_t = 8080)]
    pub port: u16,

    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub guac_url: String,

    #[arg(long = "bombastic-url", env, default_value = "http://localhost:8082")]
    pub bombastic_url: reqwest::Url,

    #[arg(long = "vexination-url", env, default_value = "http://localhost:8081")]
    pub vexination_url: reqwest::Url,

    #[arg(long = "crda-url", env)]
    pub crda_url: Option<reqwest::Url>,

    #[arg(long = "crda-payload-limit", env, default_value_t = DEFAULT_CRDA_PAYLOAD_LIMIT)]
    pub crda_payload_limit: usize,

    /// Path to the UI configuration file, overriding the default configuration file.
    #[arg(short, long = "config", env = "SPOG_UI_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub oidc: AuthenticatorConfig,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,
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
