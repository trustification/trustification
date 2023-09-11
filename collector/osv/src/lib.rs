use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use reqwest::Url;
use tokio::sync::RwLock;

use crate::client::OsvClient;
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};
use trustification_infrastructure::{
    endpoint::{self, CollectorOsv, Endpoint, EndpointServerConfig},
    Infrastructure, InfrastructureConfig,
};

use crate::client::schema::{Reference, Vulnerability};
use crate::server::{deregister_with_collectorist, register_with_collectorist};

mod client;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<CollectorOsv>,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        env,
        short = 'u',
        long = "collectorist-url",
        default_value_t = endpoint::Collectorist::url()
    )]
    pub(crate) collectorist_url: Url,

    #[arg(
        env,
        short = 'v',
        long = "v11y-url",
        default_value_t = endpoint::V11y::url()
    )]
    pub(crate) v11y_url: Url,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        if self.devmode {
            self.v11y_url = Url::parse("http://localhost:8087").unwrap();
            self.collectorist_url = Url::parse("http://localhost:8088").unwrap();
        }

        Infrastructure::from(self.infra)
            .run("collector-osv", |_metrics| async move {
                let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                let state = Self::configure("osv".into(), self.collectorist_url, self.v11y_url, provider).await?;
                let server = server::run(state.clone(), self.api.socket_addr()?);
                let register = register_with_collectorist(&state);

                tokio::select! {
                     _ = server => { }
                     _ = register => { }
                }

                deregister_with_collectorist(&state).await;
                Ok(())
            })
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure<P>(
        collector_id: String,
        collectorist_url: Url,
        v11y_url: Url,
        provider: P,
    ) -> anyhow::Result<Arc<AppState>>
    where
        P: TokenProvider + Clone + 'static,
    {
        let state = Arc::new(AppState::new(collector_id, collectorist_url, v11y_url, provider));
        Ok(state)
    }
}

pub struct AppState {
    addr: RwLock<Option<SocketAddr>>,
    connected: AtomicBool,
    collectorist_client: collectorist_client::CollectoristClient,
    v11y_client: v11y_client::V11yClient,
    guac_url: RwLock<Option<Url>>,
    osv: OsvClient,
}

impl AppState {
    pub fn new<P>(collector_id: String, collectorist_url: Url, v11y_url: Url, provider: P) -> Self
    where
        P: TokenProvider + Clone + 'static,
    {
        Self {
            addr: RwLock::new(None),
            connected: AtomicBool::new(false),
            collectorist_client: collectorist_client::CollectoristClient::new(
                collector_id,
                collectorist_url,
                provider.clone(),
            ),
            v11y_client: v11y_client::V11yClient::new(v11y_url, provider),
            guac_url: RwLock::new(None),
            osv: OsvClient::new(),
        }
    }
}

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
            aliases: vuln.aliases.clone().unwrap_or(Default::default()),
            affected: vec![],
            severities: Default::default(),
            related: vuln.related.clone().unwrap_or(Default::default()),
            references: vuln
                .references
                .unwrap_or(Default::default())
                .iter()
                .map(|e| e.into())
                .collect(),
        }
    }
}

impl From<&Reference> for v11y_client::Reference {
    fn from(reference: &Reference) -> Self {
        Self {
            r#type: reference.reference_type.to_string(),
            url: reference.url.clone(),
        }
    }
}
