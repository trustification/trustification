mod advisory;
mod analytics;
mod analyze;
mod app_state;
mod config;
mod cve;
mod endpoints;
mod error;
mod guac;
mod index;
mod openapi;
mod package;
mod sbom;
mod search;
mod server;
mod service;
mod utils;

use std::process::ExitCode;
use std::{net::TcpListener, path::PathBuf};
use trustification_analytics::AnalyticsConfig;
use trustification_auth::{
    auth::AuthConfigArguments, client::OpenIdTokenProviderConfigArguments, swagger_ui::SwaggerUiOidcConfig,
};
use trustification_common::tls::ClientConfig;
use trustification_infrastructure::{
    app::http::HttpServerConfig,
    endpoint::{self, Endpoint, SpogApi},
    Infrastructure, InfrastructureConfig,
};
use url::Url;

// export the API documentation
pub use server::ApiDoc;

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

    #[arg(short = 'g', long = "guac", default_value_t = endpoint::GuacGraphQl::url())]
    pub guac_url: Url,

    #[arg(long = "bombastic-url", env, default_value_t = endpoint::Bombastic::url())]
    pub bombastic_url: Url,

    #[arg(long = "vexination-url", env, default_value_t = endpoint::Vexination::url())]
    pub vexination_url: Url,

    #[arg(long = "exhort-url", env, default_value_t = endpoint::Exhort::url())]
    pub exhort_url: Url,

    #[arg(long = "crda-url", env)]
    pub crda_url: Option<Url>,

    #[arg(long = "collectorist-url", env, default_value_t = endpoint::Collectorist::url())]
    pub collectorist_url: Url,

    #[arg(long = "v11y-url", env, default_value_t = endpoint::V11y::url())]
    pub v11y_url: Url,

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

    #[command(flatten)]
    pub http: HttpServerConfig<SpogApi>,

    #[command(flatten)]
    pub client: ClientConfig,
}

impl Run {
    pub async fn run(self, listener: Option<TcpListener>) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra.clone())
            .run(
                "spog-api",
                |_context| async { Ok(()) },
                |context| async move {
                    let s = server::Server::new(self);
                    s.run(context, listener).await
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}
