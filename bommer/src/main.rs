mod bombastic;
mod pubsub;
mod server;
mod store;
mod workload;

use crate::bombastic::BombasticSource;
use crate::server::ServerConfig;
use crate::store::image_store;
use futures::FutureExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{runtime::watcher, Api, Client};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let client = Client::try_default().await?;

    let api: Api<Pod> = Api::all(client);

    let stream = watcher(
        api,
        watcher::Config {
            ..Default::default()
        },
    );

    let url =
        std::env::var("BOMBASTIC_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let source = BombasticSource::new(url.parse()?);

    let (store, runner) = image_store(stream);

    if false {
        let store = store.clone();
        tokio::spawn(async move {
            loop {
                info!("Starting event stream");
                let mut sub = store.subscribe(16).await;
                while let Some(evt) = sub.recv().await {
                    info!("Event: {evt:?}");
                }
            }
        });
    }

    // SBOM scanner

    let (map, runner2) = bombastic::store(store.clone(), source);

    {
        let map = map.clone();
        tokio::spawn(async move {
            loop {
                info!("Starting SBOM stream");
                let mut sub = map.subscribe(16).await;
                while let Some(evt) = sub.recv().await {
                    info!("Event: {evt:?}");
                }
                warn!("Lost debug subscription");
            }
        });
    }

    // server

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "[::]:8080".to_string());

    info!("Binding to {bind_addr}");

    let config = ServerConfig { bind_addr };

    let server = server::run(config, map);

    let (result, _, _) = futures::future::select_all([
        server.boxed_local(),
        runner.boxed_local(),
        runner2.boxed_local(),
    ])
    .await;

    result?;

    Ok(())
}
