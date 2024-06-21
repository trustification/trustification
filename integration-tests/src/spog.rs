use super::*;
use crate::{
    config::Config,
    provider::{IntoTokenProvider, ProviderKind},
    runner::Runner,
};
use async_trait::async_trait;
use test_context::AsyncTestContext;
use trustification_auth::client::{OpenIdTokenProviderConfigArguments, TokenProvider};

#[async_trait]
impl AsyncTestContext for SpogContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_spog(&config).await
    }

    async fn teardown(self) {
        self.bombastic.teardown().await;
        self.vexination.teardown().await;
    }
}

impl Urlifier for SpogContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

impl IntoTokenProvider for SpogContext {
    fn token_provider(&self, kind: ProviderKind) -> &dyn TokenProvider {
        match kind {
            ProviderKind::User => &self.provider.provider_user,
            ProviderKind::Manager => &self.provider.provider_manager,
        }
    }
}

pub struct SpogContext {
    pub url: Url,
    pub provider: ProviderContext,

    pub bombastic: BombasticContext,
    pub vexination: VexinationContext,

    _runner: Option<Runner>,
}

pub async fn start_spog(config: &Config) -> SpogContext {
    // If remote server is configured, use it
    if let Some(url) = config.spog.clone() {
        log::debug!("Testing remote spog: {url}");
        return SpogContext {
            url,
            provider: config.provider().await,
            bombastic: start_bombastic(config).await,
            vexination: start_vexination(config).await,
            _runner: None,
        };
    }

    {
        use trustification_infrastructure::endpoint;
        use trustification_infrastructure::endpoint::Endpoint;
        // No remote server requested, so fire up spog on ephemeral port
        let (listener, _, url) = tcp_connection();

        let bombastic = start_bombastic(config).await;
        let vexination = start_vexination(config).await;

        let burl = bombastic.url.to_owned();
        let vurl = vexination.url.to_owned();
        // FIXME: use from start_* once we have it
        let curl = endpoint::Collectorist::url();
        let wurl = endpoint::V11y::url();
        let eurl = endpoint::Exhort::url();

        let runner = Runner::spawn(move || async move {
            select! {
                biased;

                spog = spog_api(burl, vurl, curl, wurl, eurl).run(Some(listener)) => match spog {
                    Err(e) => {
                        panic!("Error running spog API: {e:?}");
                    }
                    Ok(code) => {
                        log::info!("Spog API exited with code {code:?}");
                    }
                },
            }

            Ok(())
        });

        // Create context right after spawning, as we clean up as soon as the context drops
        let context = SpogContext {
            url,
            provider: config.provider().await,
            bombastic,
            vexination,
            _runner: Some(runner),
        };

        // Ensure it's initialized
        wait_on_service(&context, "sbom", "id").await;

        // Return the context
        context
    }
}

fn spog_api(
    bombastic_url: Url,
    vexination_url: Url,
    collectorist_url: Url,
    v11y_url: Url,
    exhort_url: Url,
) -> spog_api::Run {
    use trustification_infrastructure::endpoint;
    use trustification_infrastructure::endpoint::Endpoint;

    spog_api::Run {
        client: Default::default(),
        devmode: false,
        guac_url: endpoint::GuacGraphQl::url(),
        bombastic_url,
        vexination_url,
        exhort_url,
        crda_url: option_env!("CRDA_URL").map(|url| url.parse().unwrap()),
        crda_payload_limit: DEFAULT_CRDA_PAYLOAD_LIMIT,
        snyk_token: None,
        collectorist_url,
        v11y_url,
        oidc: OpenIdTokenProviderConfigArguments::devmode(),
        config: None,
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
        auth: testing_auth(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
        analytics: Default::default(),
        http: Default::default(),
    }
}
