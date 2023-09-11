use std::process::ExitCode;
use std::{net::TcpListener, path::PathBuf};
use trustification_analytics::AnalyticsConfig;
use trustification_auth::client::OpenIdTokenProviderConfigArguments;
use trustification_auth::{auth::AuthConfigArguments, swagger_ui::SwaggerUiOidcConfig};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use url::Url;

mod advisory;
mod analytics;
mod analyze;
mod config;
mod cve;
mod guac;
mod index;
mod sbom;
mod search;
mod server;
mod service;

pub const DEFAULT_CRDA_PAYLOAD_LIMIT: usize = 10 * 1024 * 1024;

/// Run the API server
#[derive(clap::Args, Debug)]
#[command(
    about = "Run the api server",
    args_conflicts_with_subcommands = true,
    rename_all_env = "SCREAMING_SNAKE_CASE"
)]
pub struct Run {
    /// Enable developer mode
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(short, long, env, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", env, default_value_t = 8080)]
    pub port: u16,

    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8085/query")]
    pub guac_url: String,

    #[arg(long = "bombastic-url", env, default_value = "http://localhost:8082")]
    pub bombastic_url: Url,

    #[arg(long = "vexination-url", env, default_value = "http://localhost:8081")]
    pub vexination_url: Url,

    #[arg(long = "crda-url", env)]
    pub crda_url: Option<Url>,

    #[arg(long = "collectorist-url", env)]
    pub collectorist_url: Option<Url>,

    #[arg(long = "v11y-url", env)]
    pub v11y_url: Option<Url>,

    #[arg(long = "crda-payload-limit", env, default_value_t = DEFAULT_CRDA_PAYLOAD_LIMIT)]
    pub crda_payload_limit: usize,

    /// Path to the UI configuration file, overriding the default configuration file.
    #[arg(short, long = "config", env = "SPOG_UI_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub analytics: AnalyticsConfig,
}

impl Run {
    pub async fn run(mut self, listener: Option<TcpListener>) -> anyhow::Result<ExitCode> {
        if self.devmode {
            self.collectorist_url = Some(Url::parse("http://localhost:8088").unwrap());
            self.v11y_url = Some(Url::parse("http://localhost:8087").unwrap());
        }

        Infrastructure::from(self.infra.clone())
            .run("spog-api", |metrics| async move {
                let s = server::Server::new(self);
                s.run(metrics.registry(), listener).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
