use super::*;
use crate::runner::Runner;
use async_trait::async_trait;
use test_context::AsyncTestContext;

pub struct VexinationContext {
    pub provider: ProviderContext,
    pub port: u16,

    _runner: Runner,
}

pub async fn start_vexination(provider: ProviderContext) -> VexinationContext {
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let runner = Runner::spawn(|| async {
        select! {
            biased;

            vindexer = vexination_indexer().run() => match vindexer {
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

    let context = VexinationContext {
        port,
        provider,
        _runner: runner,
    };

    // ensure it's initialized

    let client = reqwest::Client::new();
    loop {
        let response = client
            .get(format!("http://localhost:{port}/api/v1/vex?advisory=none"))
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
impl AsyncTestContext for VexinationContext {
    async fn setup() -> Self {
        let provider = create_provider_context().await;
        start_vexination(provider).await
    }
}
