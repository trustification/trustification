use actix_web::web;
use prometheus::Registry;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::block_in_place;
use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::health::checks::Probe;
use trustification_infrastructure::{
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::V11y,
    Infrastructure, InfrastructureConfig,
};
use trustification_storage::{Storage, StorageConfig};

use crate::db::Db;

mod db;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    /// Base path to the database store. Defaults to the local directory.
    #[arg(env, long = "storage-base")]
    pub(crate) storage_base: Option<PathBuf>,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub http: HttpServerConfig<V11y>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let index = self.index;
        let storage = self.storage;

        let (authn, authz) = self.auth.split(self.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        let swagger_oidc: Option<Arc<SwaggerUiOidc>> =
            SwaggerUiOidc::from_devmode_or_config(self.devmode, self.swagger_ui_oidc)
                .await?
                .map(Arc::new);

        if authenticator.is_none() {
            log::warn!("Authentication is disabled");
        }

        let tracing = self.infra.tracing;

        Infrastructure::from(self.infra)
            .run(
                "v11y",
                |_context| async { Ok(()) },
                |context| async move {
                    let (probe, check) = Probe::new("Index not synced");
                    context.health.readiness.register("available.index", check).await;

                    let state = Self::configure(
                        self.storage_base,
                        index,
                        storage,
                        probe,
                        context.metrics.registry(),
                        self.devmode,
                    )
                    .await?;

                    let http = HttpServerBuilder::try_from(self.http)?
                        .tracing(tracing)
                        .metrics(context.metrics.registry().clone(), "v11y_api")
                        .authorizer(authorizer.clone())
                        .configure(move |svc| {
                            let authenticator = authenticator.clone();
                            let swagger_oidc = swagger_oidc.clone();

                            svc.app_data(web::Data::from(state.clone()))
                                .configure(|cfg| server::config(cfg, authenticator, swagger_oidc));
                        });

                    http.run().await
                },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }

    async fn configure(
        base: Option<PathBuf>,
        index_config: IndexConfig,
        storage: StorageConfig,
        probe: Probe,
        registry: &Registry,
        devmode: bool,
    ) -> anyhow::Result<Arc<AppState>> {
        let base = base.unwrap_or_else(|| ".".into());

        let index = block_in_place(|| IndexStore::new(&storage, &index_config, v11y_index::Index::new(), registry))?;
        let storage = Storage::new(storage.process("v11y", devmode), registry)?;

        let state = Arc::new(AppState::new(base, storage, index).await?);

        let sinker = state.clone();
        let sync_interval = index_config.sync_interval.into();
        tokio::task::spawn(async move {
            loop {
                if sinker.sync_index().await.is_ok() {
                    log::info!("Initial CVE index synced");
                    break;
                } else {
                    log::warn!("CVE index not yet available");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            probe.set(true);

            loop {
                if let Err(e) = sinker.sync_index().await {
                    log::info!("Unable to synchronize v11y index: {:?}", e);
                }
                tokio::time::sleep(sync_interval).await;
            }
        });

        Ok(state)
    }
}

#[allow(unused)]
pub struct AppState {
    db: Db,

    storage: Storage,
    index: IndexStore<v11y_index::Index>,
}

impl AppState {
    pub async fn new(
        base: impl AsRef<Path>,
        storage: Storage,
        index: IndexStore<v11y_index::Index>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            db: Db::new(base).await?,
            storage,
            index,
        })
    }

    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let storage = &self.storage;
        let index = &self.index;
        index.sync(storage).await?;
        Ok(())
    }
}
