mod bombastic;
mod pubsub;
mod server;
mod store;
mod workload;

use clap::Parser;
use futures::FutureExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{runtime::watcher, Api, Client};
use log::{info, warn};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

use crate::{bombastic::BombasticSource, server::ServerConfig, store::image_store};

#[derive(Clone, Debug, clap::Parser)]
pub struct Cli {
    #[arg(long, env, default_value = "http://localhost:8080")]
    bombastic_url: String,

    #[arg(long, env, default_value = "[::1]:8080")]
    bind: String,

    #[command(flatten)]
    infra: InfrastructureConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::try_init();

    let cli = Cli::parse();

    let client = Client::try_default().await?;

    let api: Api<Pod> = Api::all(client);

    let stream = watcher(api, watcher::Config { ..Default::default() });

    let source = BombasticSource::new(cli.bombastic_url.parse()?);

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

    let bind_addr = cli.bind;
    info!("Binding to {bind_addr}");
    let config = ServerConfig { bind_addr };

    Infrastructure::from(cli.infra)
        .run("bommber", || async {
            let server = server::run(config, map);

            let (result, _, _) =
                futures::future::select_all([server.boxed_local(), runner.boxed_local(), runner2.boxed_local()]).await;

            result
        })
        .await
}
