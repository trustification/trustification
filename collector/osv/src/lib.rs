use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use reqwest::Url;

use tokio::sync::RwLock;

use trustification_infrastructure::{defaults::{self, Endpoint}, Infrastructure, InfrastructureConfig};

use crate::client::schema::{Reference, Vulnerability};
use crate::server::{deregister_with_collectorist, register_with_collectorist};

mod client;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(
        short = 'p',
        long = "port",
        default_value_t = defaults::CollectorOsv::port()
    )]
    pub port: u16,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        env,
        short = 'u',
        long = "collectorist-url",
        default_value_t = defaults::Collectorist::url()
    )]
    pub(crate) collectorist_url: Url,

    #[arg(
        env,
        short = 'v',
        long = "v11y-url",
        default_value_t = defaults::V11y::url()
    )]
    pub(crate) v11y_url: Url,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("collector-osv", |_metrics| async move {
                let state = Self::configure("osv".into(), self.collectorist_url.to_string(), self.v11y_url.to_string()).await?;
                let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
                let server = server::run(state.clone(), addr);
                let register = register_with_collectorist(state.clone());

                tokio::select! {
                     _ = server => { }
                     _ = register => { }
                }

                deregister_with_collectorist(state.clone()).await;
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(
        collector_id: String,
        collectorist_url: String,
        v11y_url: String,
    ) -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState::new(collector_id, collectorist_url, v11y_url));
        Ok(state)
    }
}

pub struct AppState {
    addr: RwLock<Option<SocketAddr>>,
    connected: AtomicBool,
    collectorist_client: collectorist_client::CollectoristClient,
    v11y_client: v11y_client::V11yClient,
    guac_url: RwLock<Option<String>>,
}

impl AppState {
    pub fn new(collector_id: String, collectorist_url: String, v11y_url: String) -> Self {
        Self {
            addr: RwLock::new(None),
            connected: AtomicBool::new(false),
            collectorist_client: collectorist_client::CollectoristClient::new(collector_id, collectorist_url),
            v11y_client: v11y_client::V11yClient::new(v11y_url),
            guac_url: RwLock::new(None),
        }
    }
}

pub(crate) type SharedState = Arc<AppState>;

impl From<Vulnerability> for v11y_client::Vulnerability {
    fn from(vuln: Vulnerability) -> Self {
        Self {
            origin: "osv".to_string(),
            id: vuln.id,
            modified: vuln.modified,
            published: vuln.published,
            withdrawn: vuln.withdrawn,
            summary: vuln.summary.clone().unwrap_or("".to_string()),
            details: vuln.details.clone().unwrap_or("".to_string()),
            aliases: HashSet::from_iter(vuln.aliases.clone().unwrap_or(Default::default())),
            affected: vec![],
            severities: Default::default(),
            related: HashSet::from_iter(vuln.related.clone().unwrap_or(Default::default())),
            references: HashSet::from_iter(vuln.references.unwrap_or(Default::default()).iter().map(|e| e.into())),
        }
    }
}

impl From<&Reference> for v11y_client::Reference {
    fn from(reference: &Reference) -> Self {
        Self {
            r#type: serde_json::to_string(&reference.reference_type).unwrap_or("unknown".to_string()),
            url: reference.url.clone(),
        }
    }
}
