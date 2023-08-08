use actix_cors::Cors;
use std::{
    net::{SocketAddr, TcpListener},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use actix_web::{web, HttpServer};
use actix_web_prom::PrometheusMetricsBuilder;
use anyhow::anyhow;
use prometheus::Registry;
use tokio::sync::RwLock;
use trustification_auth::authenticator::config::AuthenticatorConfig;
use trustification_auth::authenticator::Authenticator;
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::app::{new_app, AppOptions};
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    pub port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub oidc: AuthenticatorConfig,
}

impl Run {
    pub async fn run(self, listener: Option<TcpListener>) -> anyhow::Result<ExitCode> {
        let index = self.index;
        let storage = self.storage;

        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_devmode_or_config(self.devmode, self.oidc)
            .await?
            .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        Infrastructure::from(self.infra)
            .run("vexination-api", |metrics| async move {
                let state = Self::configure(index, storage, metrics.registry(), self.devmode)?;
                let http_metrics = PrometheusMetricsBuilder::new("vexination_api")
                    .registry(metrics.registry().clone())
                    .build()
                    .map_err(|_| anyhow!("Error registering HTTP metrics"))?;
                let mut srv = HttpServer::new(move || {
                    let http_metrics = http_metrics.clone();
                    let cors = Cors::permissive();
                    let authenticator = authenticator.clone();

                    new_app(AppOptions {
                        cors: Some(cors),
                        metrics: Some(http_metrics),
                        authenticator: authenticator.clone(),
                    })
                    .app_data(web::Data::new(state.clone()))
                    .configure(server::config)
                });
                srv = match listener {
                    Some(v) => srv.listen(v)?,
                    None => {
                        let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;
                        srv.bind(addr)?
                    }
                };
                srv.run().await.map_err(anyhow::Error::msg)
            })
            .await?;
        Ok(ExitCode::SUCCESS)
    }

    fn configure(
        mut index: IndexConfig,
        mut storage: StorageConfig,
        registry: &Registry,
        devmode: bool,
    ) -> anyhow::Result<Arc<AppState>> {
        let index = tokio::task::block_in_place(|| index.create(vexination_index::Index::new(), "vexination", devmode, registry))?;
        let storage = storage.create("vexination", devmode, registry)?;

        let state = Arc::new(AppState {
            storage: RwLock::new(storage),
            index,
        });

        Ok(state)
    }
}

pub(crate) type Index = IndexStore<vexination_index::Index>;
pub struct AppState {
    storage: RwLock<Storage>,
    index: Index,
}

pub(crate) type SharedState = Arc<AppState>;
