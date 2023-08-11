use super::*;
use crate::runner::Runner;
use async_trait::async_trait;
use test_context::AsyncTestContext;

pub struct BombasticContext {
    pub provider: ProviderContext,
    pub port: u16,
    pub config: EventBusConfig,
    _runner: Runner,
}

pub async fn start_bombastic(provider: ProviderContext) -> BombasticContext {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let indexer = bombastic_indexer();
    let config = indexer.bus.clone();

    let runner = Runner::spawn(|| async {
        select! {
            biased;

            bindexer = indexer.run() => match bindexer {
                Err(e) => {
                    panic!("Error running bombastic indexer: {e:?}");
                }
                Ok(code) => {
                    println!("Bombastic indexer exited with code {code:?}");
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
        port,
        provider,
        config,
        _runner: runner,
    };

    // ensure it's initialized

    let client = reqwest::Client::new();
    loop {
        let response = client
            .get(format!("http://localhost:{port}/api/v1/sbom?id=none"))
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

pub async fn upload_sbom(port: u16, key: &str, input: &serde_json::Value, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .json(input)
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

pub async fn delete_sbom(port: u16, key: &str, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .delete(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[async_trait]
impl AsyncTestContext for BombasticContext {
    async fn setup() -> Self {
        let provider = create_provider_context().await;
        start_bombastic(provider).await
    }
}
