use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::client::schema::{Reference, Vulnerability};
use crate::client::OsvClient;
use crate::server::{deregister_with_collectorist, register_with_collectorist};
use reqwest::Url;
use tokio::sync::RwLock;
use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{OpenIdTokenProviderConfigArguments, TokenProvider},
};
use trustification_infrastructure::{
    app::http::HttpServerConfig,
    endpoint::{self, CollectorOsv, Endpoint},
    health::checks::AtomicBoolStateCheck,
    Infrastructure, InfrastructureConfig,
};

mod client;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
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

    #[arg(env, long = "advertise")]
    pub(crate) advertise: Option<Url>,

    #[arg(
        env,
        short = 'v',
        long = "v11y-url",
        default_value_t = endpoint::V11y::url()
    )]
    pub(crate) v11y_url: Url,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub(crate) http: HttpServerConfig<CollectorOsv>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let (authn, authz) = self.auth.split(self.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        Infrastructure::from(self.infra)
            .run(
                "collector-osv",
                |_context| async move { Ok(()) },
                |context| async move {
                    let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                    let state = Self::configure("osv".into(), self.collectorist_url, self.v11y_url, provider).await?;

                    context
                        .health
                        .readiness
                        .register(
                            "collectorist.registered",
                            AtomicBoolStateCheck::new(
                                state.clone(),
                                |state| &state.connected,
                                "Not registered with collectorist",
                            ),
                        )
                        .await;

                    let server = server::run(context, state.clone(), self.http, authenticator, authorizer);
                    let register = register_with_collectorist(&state, self.advertise);

                    tokio::select! {
                         t = server => { t? }
                         t = register => { t? }
                    }

                    deregister_with_collectorist(&state).await;
                    Ok(())
                },
            )
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
