use guac::client::GuacClient;
use std::process::ExitCode;
use std::sync::Arc;

use reqwest::Url;

use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    client::{OpenIdTokenProviderConfigArguments, TokenProvider},
};
use trustification_common::tls::ClientConfig;
use trustification_infrastructure::{
    app::http::HttpServerConfig,
    endpoint::CollectorSnyk,
    endpoint::{self, Endpoint},
    Infrastructure, InfrastructureConfig,
};
use v11y_client::{ScoreType, Vulnerability};

use crate::client::schema::{Issue, IssueAttributes, Reference, Severity};

//use crate::client::schema::{Reference, Vulnerability};
//use crate::server::{deregister_with_collectorist, register_with_collectorist};

//mod client;
mod client;
mod server;

mod rewrite;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(
        env = "GUAC_URL",
        long = "guac-url",
        default_value_t = endpoint::GuacGraphQl::url()
    )]
    pub(crate) guac_url: Url,

    #[arg(
        env = "V11Y_URL",
        long = "v11y-url",
        default_value_t = endpoint::V11y::url()
    )]
    pub(crate) v11y_url: Url,

    #[arg(env, long = "snyk-org-id")]
    pub(crate) snyk_org_id: String,

    #[arg(env, long = "snyk-token")]
    pub(crate) snyk_token: String,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub(crate) oidc: OpenIdTokenProviderConfigArguments,

    #[command(flatten)]
    pub(crate) http: HttpServerConfig<CollectorSnyk>,

    #[command(flatten)]
    pub(crate) client: ClientConfig,
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
                |_context| async { Ok(()) },
                |context| async move {
                    let provider = self.oidc.into_provider_or_devmode(self.devmode).await?;
                    let state = Self::configure(
                        self.client.build_client()?,
                        self.snyk_org_id,
                        self.snyk_token,
                        self.guac_url,
                        self.v11y_url,
                        provider.clone(),
                    )
                    .await?;

                    server::run(context, state.clone(), self.http, authenticator, authorizer).await
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure<P>(
        client: reqwest::Client,
        snyk_org_id: String,
        snyk_token: String,
        guac_url: Url,
        v11y_url: Url,
        provider: P,
    ) -> anyhow::Result<Arc<AppState>>
    where
        P: TokenProvider + Clone + 'static,
    {
        let state = Arc::new(AppState::new(
            client,
            snyk_org_id,
            snyk_token,
            guac_url,
            v11y_url,
            provider,
        ));
        Ok(state)
    }
}

pub struct AppState {
    v11y_client: v11y_client::V11yClient,
    guac_client: GuacClient,
    snyk_org_id: String,
    snyk_token: String,
}

impl AppState {
    pub fn new<P>(
        client: reqwest::Client,
        snyk_org_id: String,
        snyk_token: String,
        guac_url: Url,
        v11y_url: Url,
        provider: P,
    ) -> Self
    where
        P: TokenProvider + Clone + 'static,
    {
        Self {
            v11y_client: v11y_client::V11yClient::new(client, v11y_url, provider),
            guac_client: GuacClient::new(guac_url.as_str()),
            snyk_org_id,
            snyk_token,
        }
    }
}

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
