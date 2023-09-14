use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use reqwest::Url;
use tokio::sync::RwLock;

use crate::client::schema::{Issue, IssueAttributes, Reference, Severity};
use crate::server::{deregister_with_collectorist, register_with_collectorist};
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};
use trustification_infrastructure::endpoint::CollectorSnyk;
use trustification_infrastructure::health::checks::AtomicBoolStateCheck;
use trustification_infrastructure::{
    endpoint::{self, Endpoint, EndpointServerConfig},
    Infrastructure, InfrastructureConfig,
};
use v11y_client::{ScoreType, Vulnerability};

//use crate::client::schema::{Reference, Vulnerability};
//use crate::server::{deregister_with_collectorist, register_with_collectorist};

//mod client;
mod client;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<CollectorSnyk>,

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

    #[arg(env, long = "snyk-org-id")]
    pub(crate) snyk_org_id: String,

    #[arg(env, long = "snyk-token")]
    pub(crate) snyk_token: String,

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
            .run(
                "collector-osv",
                |_context| async { Ok(()) },
                |context| async move {
                    let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                    let state = Self::configure(
                        self.snyk_org_id,
                        self.snyk_token,
                        "snyk".into(),
                        self.collectorist_url,
                        self.v11y_url,
                        provider,
                    )
                    .await?;

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

                    let server = server::run(state.clone(), self.api.socket_addr()?);
                    let register = register_with_collectorist(state.clone(), self.advertise);

                    tokio::select! {
                         _ = server => { }
                         _ = register => { }
                    }

                    deregister_with_collectorist(state.clone()).await;
                    Ok(())
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure<P>(
        snyk_org_id: String,
        snyk_token: String,
        collector_id: String,
        collectorist_url: Url,
        v11y_url: Url,
        provider: P,
    ) -> anyhow::Result<Arc<AppState>>
    where
        P: TokenProvider + Clone + 'static,
    {
        let state = Arc::new(AppState::new(
            snyk_org_id,
            snyk_token,
            collector_id,
            collectorist_url,
            v11y_url,
            provider,
        ));
        Ok(state)
    }
}

pub struct AppState {
    addr: RwLock<Option<SocketAddr>>,
    connected: AtomicBool,
    collectorist_client: collectorist_client::CollectoristClient,
    v11y_client: v11y_client::V11yClient,
    guac_url: RwLock<Option<Url>>,
    snyk_org_id: String,
    snyk_token: String,
}

impl AppState {
    pub fn new<P>(
        snyk_org_id: String,
        snyk_token: String,
        collector_id: String,
        collectorist_url: Url,
        v11y_url: Url,
        provider: P,
    ) -> Self
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
            snyk_org_id,
            snyk_token,
        }
    }
}

pub(crate) type SharedState = Arc<AppState>;

impl From<Issue> for Vec<v11y_client::Vulnerability> {
    fn from(value: Issue) -> Self {
        value.attributes.into()
    }
}

impl From<IssueAttributes> for Vec<v11y_client::Vulnerability> {
    fn from(issue: IssueAttributes) -> Self {
        let mut vulns = Vec::new();

        let severities: Vec<_> = issue.severities.iter().map(|e| e.into()).collect();
        let references = issue
            .slots
            .map(|slot| slot.references.iter().map(|e| e.into()).collect())
            .unwrap_or(vec![]);

        for problem in issue.problems {
            let vuln = Vulnerability {
                origin: "snyk".to_string(),
                id: problem.id.clone(),
                modified: problem
                    .updated_at
                    .unwrap_or(problem.disclosed_at.unwrap_or(Default::default())),
                published: problem.disclosed_at.unwrap_or(Default::default()),
                withdrawn: None,
                summary: "".to_string(),
                details: issue.description.clone().unwrap_or("".to_string()),
                aliases: vec![issue.key.clone()],
                affected: vec![],
                severities: severities.clone(),
                related: vec![],
                references: references.clone(),
            };

            vulns.push(vuln)
        }

        vulns
    }
}

impl From<&Severity> for v11y_client::Severity {
    fn from(value: &Severity) -> Self {
        Self {
            r#type: ScoreType::from_vector(&value.vector),
            source: value.source.clone(),
            score: value.score.unwrap_or(0.0),
            additional: value.vector.clone(),
        }
    }
}

impl From<&Reference> for v11y_client::Reference {
    fn from(value: &Reference) -> Self {
        Self {
            r#type: value.title.as_ref().unwrap_or(&"WEB".to_string()).clone(),
            url: value.url.as_ref().unwrap_or(&"".to_string()).clone(),
        }
    }
}
