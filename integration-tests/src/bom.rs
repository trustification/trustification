use super::*;
use crate::{config::Config, runner::Runner};
use async_trait::async_trait;
use bytesize::ByteSize;
use reqwest::Url;
use test_context::AsyncTestContext;
use trustification_indexer::ReindexMode;

#[async_trait]
impl AsyncTestContext for BombasticContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_bombastic(&config).await
    }
    async fn teardown(self) {
        for id in &self.fixtures {
            self.delete_sbom(id).await;
        }
    }
}

impl Urlifier for BombasticContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

pub struct BombasticContext {
    pub url: Url,
    pub provider: ProviderContext,
    _runner: Option<Runner>,
    fixtures: Vec<String>,
}

pub async fn start_bombastic(config: &Config) -> BombasticContext {
    // If remote server is configured, use it
    if let Some(url) = config.bombastic.clone() {
        log::debug!("Testing remote bombastic: {url}");
        return BombasticContext {
            url,
            provider: config.provider().await,
            _runner: None,
            fixtures: Vec::new(),
        };
    }

    {
        // No remote server requested, so fire up bombastic on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();

        let runner = Runner::spawn(|| async {
            select! {
                biased;

                bindexer = bombastic_indexer().run() => match bindexer {
                    Err(e) => {
                        panic!("Error running bombastic indexer: {e:?}");
                    }
                    Ok(code) => {
                        println!("Bombastic indexer exited with code {code:?}");
                    }
                },
                vindexer = vexination_indexer().run() => match vindexer {
                    Err(e) => {
                        panic!("Error running vexination indexer: {e:?}");
                    }
                    Ok(code) => {
                        println!("Vexination indexer exited with code {code:?}");
                    }
                },
                bapi = bombastic_api().run(Some(listener)) => match bapi {
                    Err(e) => {
                        panic!("Error running bombastic API: {e:?}");
                    }
                    Ok(code) => {
                        println!("Bombastic API exited with code {code:?}");
                    }
                },
            }

            Ok(())
        });

        // Create context right after spawning, as we clean up as soon as the context drops
        let context = BombasticContext {
            url,
            provider: config.provider().await,
            _runner: Some(runner),
            fixtures: Vec::new(),
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

impl BombasticContext {
    pub async fn upload_sbom(&mut self, key: &str, input: &serde_json::Value) {
        let response = reqwest::Client::new()
            .post(self.urlify(format!("/api/v1/sbom?id={key}")))
            .json(input)
            .inject_token(&self.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        self.fixtures.push(key.to_string());
    }

    pub async fn delete_sbom(&self, key: &str) {
        let response = reqwest::Client::new()
            .delete(self.urlify(format!("/api/v1/sbom?id={key}")))
            .inject_token(&self.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

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

pub async fn wait_for_package_search_result<F: Fn(&serde_json::Value) -> bool>(
    context: &mut BombasticContext,
    flags: &[(&str, &str)],
    check: F,
) -> serde_json::Value {
    wait_for_search_result(context, flags, check, "/api/v1/package/search").await
}

pub async fn wait_for_sbom_search_result<F: Fn(&serde_json::Value) -> bool>(
    context: &mut BombasticContext,
    flags: &[(&str, &str)],
    check: F,
) -> serde_json::Value {
    wait_for_search_result(context, flags, check, "/api/v1/sbom/search").await
}

async fn wait_for_search_result<F: Fn(&serde_json::Value) -> bool>(
    context: &mut BombasticContext,
    flags: &[(&str, &str)],
    check: F,
    path: &str,
) -> serde_json::Value {
    loop {
        let url = context.urlify(path);
        let response = reqwest::Client::new()
            .get(url)
            .query(flags)
            .inject_token(&context.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload: Value = response.json().await.unwrap();
        if check(&payload) {
            return payload;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// Configuration for the bombastic indexer
fn bombastic_indexer() -> bombastic_indexer::Run {
    bombastic_indexer::Run {
        stored_topic: "sbom-stored".into(),
        failed_topic: "sbom-failed".into(),
        indexed_topic: "sbom-indexed".into(),
        devmode: true,
        reindex: Default::default(),
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: None,
            bucket: Some("bombastic".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validate: false,
        },
        bus: EventBusConfig {
            event_bus: EventBusType::Kafka,
            kafka_bootstrap_servers: KAFKA_BOOTSTRAP_SERVERS.into(),
            ..Default::default()
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
    }
}

fn bombastic_api() -> bombastic_api::Run {
    use trustification_storage::Region;
    bombastic_api::Run {
        devmode: false,
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
        storage: StorageConfig {
            region: Some(Region::Custom {
                endpoint: STORAGE_ENDPOINT.into(),
                region: Region::EuCentral1.to_string(),
            }),
            bucket: Some("bombastic".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validate: true,
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
        auth: testing_auth(),
        swagger_ui_oidc: testing_swagger_ui_oidc(),
        http: Default::default(),
        publish_limit: ByteSize::mib(64).into(),
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
            bucket: Some("bombastic".into()),
            endpoint: Some(STORAGE_ENDPOINT.into()),
            access_key: Some("admin".into()),
            secret_key: Some("password".into()),
            validate: false,
        },
        infra: InfrastructureConfig {
            infrastructure_enabled: false,
            infrastructure_bind: "127.0.0.1".into(),
            infrastructure_workers: 1,
            tracing: Default::default(),
        },
        index: IndexConfig {
            index_dir: None,
            index_writer_memory_bytes: bytesize::ByteSize::mb(64),
            mode: Default::default(),
            sync_interval: Duration::from_secs(2).into(),
        },
    }
}
