use super::*;
use crate::runner::Runner;
use async_trait::async_trait;
use test_context::AsyncTestContext;

pub struct SpogContext {
    pub provider: ProviderContext,
    pub port: u16,

    pub bombastic: BombasticContext,
    pub vexination: VexinationContext,

    _runner: Runner,
}

pub async fn start_spog(provider: ProviderContext) -> SpogContext {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let bombastic = start_bombastic(provider.clone()).await;
    let vexination = start_vexination(provider.clone()).await;

    let bport = bombastic.port;
    let vport = vexination.port;

    let runner = Runner::spawn(move || async move {
        select! {
            biased;

            spog = spog_api(bport, vport).run(Some(listener)) => match spog {
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
        port,
        provider,
        bombastic,
        vexination,
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

#[async_trait]
impl AsyncTestContext for SpogContext {
    async fn setup() -> Self {
        let provider = create_provider_context().await;
        start_spog(provider).await
    }
}
