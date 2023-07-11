use std::process::ExitCode;

use reqwest::Url;
use std::str::FromStr;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod advisory;
//mod guac;
//mod snyk;
mod index;
//mod package;
mod sbom;
mod search;
mod server;
// mod vulnerability;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub(crate) snyk: Snyk,

    #[arg(short, long, default_value = "0.0.0.0")]
    pub(crate) bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub(crate) port: u16,

    #[arg(short = 'g', long = "guac", default_value = "http://localhost:8080/query")]
    pub(crate) guac_url: String,

    #[arg(long = "sync-interval-seconds", default_value_t = 10)]
    pub(crate) sync_interval_seconds: u64,

    #[arg(long = "bombastic-url", default_value = "http://localhost:8082")]
    pub(crate) bombastic_url: reqwest::Url,

    #[arg(long = "vexination-url", default_value = "http://localhost:8081")]
    pub(crate) vexination_url: reqwest::Url,

    #[command(flatten)]
    pub(crate) infra: InfrastructureConfig,
}

impl Default for Run {
    fn default() -> Self {
        Self {
            snyk: Snyk { org: None, token: None },
            bind: "127.0.0.1".to_string(),
            port: 8084,
            guac_url: "http://localhost:8080/query".to_string(),
            sync_interval_seconds: 10,
            bombastic_url: Url::from_str("http://localhost:8082").unwrap(),
            vexination_url: Url::from_str("http://localhost:8081").unwrap(),
            infra: InfrastructureConfig {
                infrastructure_enabled: false,
                infrastructure_bind: "127.0.0.1".into(),
                infrastructure_workers: 1,
                enable_tracing: false,
            },
        }
    }
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra.clone())
            .run("spog-api", |metrics| async move {
                let s = server::Server::new(self);
                s.run(metrics.registry()).await
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug, Clone)]
#[group(required = false)]
pub struct Snyk {
    #[arg(long = "snyk-org")]
    pub(crate) org: Option<String>,

    #[arg(long = "snyk-token")]
    pub(crate) token: Option<String>,
}
