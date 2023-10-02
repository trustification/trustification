use super::*;
use crate::{config::Config, runner::Runner};
use async_trait::async_trait;
use test_context::AsyncTestContext;
use trustification_indexer::ReindexMode;

#[async_trait]
impl AsyncTestContext for VexinationContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_vexination(&config).await
    }
    async fn teardown(self) {
        for id in &self.fixtures {
            self.delete_vex(id).await;
        }
    }
}

impl Urlifier for VexinationContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

pub struct VexinationContext {
    pub url: Url,
    pub provider: ProviderContext,
    pub events: EventBusConfig,
    _runner: Option<Runner>,
    fixtures: Vec<String>,
}

pub async fn start_vexination(config: &Config) -> VexinationContext {
    // If remote server is configured, use it
    if let Some(url) = config.vexination.clone() {
        log::debug!("Testing remote vexination: {url}");
        return VexinationContext {
            url,
            provider: config.provider().await,
            events: config.events(),
            _runner: None,
            fixtures: Vec::new(),
        };
    }

    {
        // No remote server requested, so fire up vexination on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();
        let indexer = vexination_indexer();
        let events = indexer.bus.clone();

        let runner = Runner::spawn(|| async {
            select! {
                biased;

                vindexer = indexer.run() => match vindexer {
                    Err(e) => {
                        panic!("Error running vexination indexer: {e:?}");
                    }
                    Ok(code) => {
                        println!("Vexination indexer exited with code {code:?}");
                    }
                },

                vapi = vexination_api().run(Some(listener)) => match vapi {
                    Err(e) => {
                        panic!("Error running vexination API: {e:?}");
                    }
                    Ok(code) => {
                        println!("Vexination API exited with code {code:?}");
                    }
                },
            }

            Ok(())
        });

        // Create context right after spawning, as we clean up as soon as the context drops
        let provider = config.provider().await;
        let context = VexinationContext {
            url,
            provider,
            events,
            _runner: Some(runner),
            fixtures: Vec::new(),
        };

        // ensure it's initialized
        let client = reqwest::Client::new();
        loop {
            let response = client
                .get(context.urlify("/api/v1/vex?advisory=none"))
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

impl VexinationContext {
    pub async fn upload_vex(&mut self, input: &serde_json::Value) {
        let response = reqwest::Client::new()
            .post(self.urlify("/api/v1/vex"))
            .json(input)
            .inject_token(&self.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let id = input["document"]["tracking"]["id"].as_str().unwrap().to_string();
        self.fixtures.push(id);
    }

    pub async fn delete_vex(&self, key: &str) {
        let id = urlencoding::encode(key);
        let response = reqwest::Client::new()
            .delete(self.urlify(format!("/api/v1/vex?advisory={id}")))
            .inject_token(&self.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
// Configuration for the vexination indexer
fn vexination_indexer() -> vexination_indexer::Run {
    vexination_indexer::Run {
        stored_topic: "vex-stored".into(),
        indexed_topic: "vex-indexed".into(),
        failed_topic: "vex-failed".into(),
        devmode: true,
        reindex: ReindexMode::Always,
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: KAFKA_BOOTSTRAP_SERVERS.into(),
            ..Default::default()
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("vexination".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
    }
}

fn vexination_api() -> vexination_api::Run {
    use trustification_storage::Region;

    vexination_api::Run {
        devmode: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: Some(Region::Custom {
                endpoint: STORAGE_ENDPOINT.into(),
                region: Region::EuCentral1.to_string(),
            }),
            bucket: Some("vexination".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        },
        auth: testing_auth(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
        http: Default::default(),
    }
}
