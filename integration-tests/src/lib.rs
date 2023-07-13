use core::future::Future;
use reqwest::StatusCode;
use std::{net::TcpListener, thread, time::Duration};
use tokio::{select, task::LocalSet, time::timeout};

pub fn with_bombastic<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt = LocalSet::new();
    runtime.block_on(rt.run_until(async move {
        select! {
            biased;

            bindexer = bombastic_indexer::Run::default().run() => match bindexer {
                Err(e) => {
                    panic!("Error running bombastic indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic indexer exited with code {:?}", code);
                }
            },
            bapi = bombastic_api::Run::default().run(Some(listener)) => match bapi {
                Err(e) => {
                    panic!("Error running bombastic API: {:?}", e);
                }
                Ok(code) => {
                    println!("Bombastic API exited with code {:?}", code);
                }
            },

            _ = async move {
                let client = reqwest::Client::new();
                // Probe bombastic API
                loop {
                    let response = client
                        .get(format!("http://localhost:{}/api/v1/sbom?id=none", port))
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

pub fn with_vexination<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::try_init();

    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rt = LocalSet::new();
    runtime.block_on(rt.run_until(async move {
        select! {
            biased;

            vindexer = vexination_indexer::Run::default().run() => match vindexer {
                Err(e) => {
                    panic!("Error running vexination indexer: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination indexer exited with code {:?}", code);
                }
            },

            vapi = vexination_api::Run::default().run(Some(listener)) => match vapi {
                Err(e) => {
                    panic!("Error running vexination API: {:?}", e);
                }
                Ok(code) => {
                    println!("Vexination API exited with code {:?}", code);
                }
            },

            _ = async move {
                let client = reqwest::Client::new();
                // Probe vexination API
                loop {
                    let response = client
                        .get(format!("http://localhost:{}/api/v1/vex?advisory=none", port))
                        .send()
                        .await
                        .unwrap();
                    if response.status() == StatusCode::NOT_FOUND {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                // Run test
                test(port).await
            } => {
                println!("Test completed");
            }
            _ = tokio::time::sleep(timeout) => {
                panic!("Test timed out");
            }
        }
    }))
}

/// Run a test with trustification infrastructure. This prepares these services:
///
/// - Bombastic API
/// - Bombastic Indexer
/// - Vexination API
/// - Vexination Indexer
pub fn run_test<F, Fut>(timeout: Duration, test: F)
where
    F: FnOnce(u16, u16) -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    with_bombastic(timeout, |bport| async move {
        thread::spawn(move || with_vexination(timeout, |vport| async move { test(bport, vport).await }))
            .join()
            .expect("Thread panicked")
    })
}

pub async fn assert_within_timeout<F: Future>(t: Duration, f: F) {
    let result = timeout(t, f).await;
    assert!(
        result.is_ok(),
        "Unable to perform operation successfully within timeout"
    );
}
