use super::*;
use crate::{config::Config, runner::Runner};
use async_trait::async_trait;
use test_context::AsyncTestContext;
use trustification_auth::client::OpenIdTokenProviderConfigArguments;

#[async_trait]
impl AsyncTestContext for SpogContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_spog(&config).await
    }
    async fn teardown(self) {
        self.bombastic.teardown().await;
    }
}

impl Urlifier for SpogContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

pub struct SpogContext {
    pub provider: ProviderContext,
    pub url: Url,

    pub bombastic: BombasticContext,

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
            _runner: None,
        };
    }

    {
        use trustification_infrastructure::endpoint;
        use trustification_infrastructure::endpoint::Endpoint;
        // No remote server requested, so fire up spog on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();

        let bombastic = start_bombastic(config).await;

        let burl = bombastic.url.to_owned();
        // FIXME: use from start_* once we have it
        let curl = endpoint::Collectorist::url();
        let wurl = endpoint::V11y::url();
        let eurl = endpoint::Exhort::url();

        let runner = Runner::spawn(move || async move {
            select! {
                biased;

                spog = spog_api(burl, curl, wurl, eurl).run(Some(listener)) => match spog {
                    Err(e) => {
                        panic!("Error running spog API: {e:?}");
                    }
                    Ok(code) => {
                        println!("Spog API exited with code {code:?}");
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
            _runner: Some(runner),
        };

        // ensure it's initialized
        let client = reqwest::Client::new();
        loop {
            let response = client
                .get(context.urlify("/api/v1/sbom?id=none"))
                .inject_token(&context.provider.provider_user)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            if response.status() == StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // return the context
        context
    }
}

fn spog_api(bombastic_url: Url, collectorist_url: Url, v11y_url: Url, exhort_url: Url) -> spog_api::Run {
    use trustification_infrastructure::endpoint;
    use trustification_infrastructure::endpoint::Endpoint;

    spog_api::Run {
        client: Default::default(),
        devmode: false,
        guac_url: endpoint::GuacGraphQl::url(),
        bombastic_url,
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
