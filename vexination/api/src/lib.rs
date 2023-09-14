use actix_web::web;
use prometheus::Registry;
use std::{net::TcpListener, process::ExitCode, sync::Arc, time::Duration};
use tokio::task::block_in_place;
use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::{EndpointServerConfig, Vexination},
    health::checks::Probe,
    Infrastructure, InfrastructureConfig,
};
use trustification_storage::{Storage, StorageConfig};

mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[command(flatten)]
    pub api: EndpointServerConfig<Vexination>,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub http: HttpServerConfig,
}

impl Run {
    pub async fn run(self, listener: Option<TcpListener>) -> anyhow::Result<ExitCode> {
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

        Infrastructure::from(self.infra)
            .run(
                "vexination-api",
                |_context| async { Ok(()) },
                |context| async move {
                    let (probe, check) = Probe::new("Index not synced");
                    context.health.readiness.register("available.index", check).await;
                    let state = Self::configure(index, storage, probe, context.metrics.registry(), self.devmode)?;
                    let mut http = HttpServerBuilder::try_from(self.http)?
                        .metrics(context.metrics.registry().clone(), "vexination_api")
                        .authorizer(authorizer.clone())
                        .configure(move |svc| {
                            let authenticator = authenticator.clone();
                            let swagger_oidc = swagger_oidc.clone();

                            svc.app_data(web::Data::new(state.clone()))
                                .configure(move |svc| server::config(svc, authenticator.clone(), swagger_oidc.clone()));
                        });

                    if let Some(v) = listener {
                        // override with provided listener
                        http = http.listen(v);
                    }

                    http.run().await
                },
            )
            .await?;
        Ok(ExitCode::SUCCESS)
    }

    fn configure(
        index_config: IndexConfig,
        storage: StorageConfig,
        probe: Probe,
        registry: &Registry,
        devmode: bool,
    ) -> anyhow::Result<Arc<AppState>> {
        let index =
            block_in_place(|| IndexStore::new(&storage, &index_config, vexination_index::Index::new(), registry))?;
        let storage = Storage::new(storage.process("vexination", devmode), registry)?;

        let state = Arc::new(AppState { storage, index });

        let sinker = state.clone();
        let sync_interval = index_config.sync_interval.into();
        tokio::task::spawn(async move {
            loop {
                if sinker.sync_index().await.is_ok() {
                    log::info!("Initial vexination index synced");
                    break;
                } else {
                    log::warn!("Vexination index not yet available");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            probe.set(true);

            loop {
                if let Err(e) = sinker.sync_index().await {
                    log::info!("Unable to synchronize vexination index: {:?}", e);
                }
                tokio::time::sleep(sync_interval).await;
            }
        });

        Ok(state)
    }
}

pub(crate) type Index = IndexStore<vexination_index::Index>;
pub struct AppState {
    storage: Storage,
    index: Index,
}

pub(crate) type SharedState = Arc<AppState>;

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let storage = &self.storage;
        let index = &self.index;
        index.sync(storage).await?;
        Ok(())
    }
}
