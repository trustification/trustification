use super::*;
use crate::{config::Config, runner::Runner};
use async_trait::async_trait;
use test_context::AsyncTestContext;

#[async_trait]
impl AsyncTestContext for SpogContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_spog(&config).await
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
    pub vexination: VexinationContext,

    _runner: Option<Runner>,
}

pub async fn start_spog(config: &Config) -> SpogContext {
    // If remote server is configured, use it
    if let Some(url) = config.spog.clone() {
        return SpogContext {
            url,
            provider: config.provider().await,
            bombastic: start_bombastic(config).await,
            vexination: start_vexination(config).await,
            _runner: None,
        };
    }

    #[cfg(not(feature = "with-services"))]
    panic!("Remote trustification server expected");

    #[cfg(feature = "with-services")]
    {
        // No remote server requested, so fire up spog on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();

        let bombastic = start_bombastic(config).await;
        let vexination = start_vexination(config).await;

        let burl = bombastic.url.to_owned();
        let vurl = vexination.url.to_owned();

        let runner = Runner::spawn(move || async move {
            select! {
                biased;

                spog = spog_api(burl, vurl).run(Some(listener)) => match spog {
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
            vexination,
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

#[cfg(feature = "with-services")]
fn spog_api(burl: Url, vurl: Url) -> spog_api::Run {
    spog_api::Run {
        devmode: false,
        bind: Default::default(),
        port: 8083,
        guac_url: Default::default(),
        bombastic_url: burl,
        vexination_url: vurl,
        crda_url: option_env!("CRDA_URL").map(|url| url.parse().unwrap()),
        crda_payload_limit: DEFAULT_CRDA_PAYLOAD_LIMIT,
        config: None,
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
        oidc: testing_oidc(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
    }
}
