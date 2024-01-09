use std::{net::TcpListener, process::ExitCode, sync::Arc, time::Duration};

use actix_web::web;
use bytesize::ByteSize;
use prometheus::Registry;
use tokio::task::block_in_place;
use trustification_auth::{
    auth::AuthConfigArguments,
    authenticator::Authenticator,
    authorizer::Authorizer,
    swagger_ui::{SwaggerUiOidc, SwaggerUiOidcConfig},
};
use trustification_index::{IndexConfig, IndexStore};
use trustification_infrastructure::{
    app::http::BinaryByteSize,
    app::http::{HttpServerBuilder, HttpServerConfig},
    endpoint::Bombastic,
    health::checks::Probe,
    Infrastructure, InfrastructureConfig,
};
use trustification_storage::{Storage, StorageConfig};

mod sbom;
mod server;
mod vex;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub index: IndexConfig,

    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[command(flatten)]
    pub auth: AuthConfigArguments,

    #[command(flatten)]
    pub swagger_ui_oidc: SwaggerUiOidcConfig,

    #[command(flatten)]
    pub http: HttpServerConfig<Bombastic>,

    /// Request limit for publish requests
    #[arg(long, default_value_t = ByteSize::mib(64).into())]
    pub publish_limit: BinaryByteSize,
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

        let tracing = self.infra.tracing;
        let publish_limit = self.publish_limit.as_u64() as usize;

        Infrastructure::from(self.infra)
            .run(
                "bombastic-api",
                |_context| async { Ok(()) },
                |context| async move {
                    let (synced_probe, synced_check) = Probe::new("Index not synced");
                    let (available_probe, available_check) = Probe::new("Index unavailable (size went to zero)");

                    context.health.readiness.register("available.index", synced_check).await;
                    context
                        .health
                        .liveness
                        .register("available.index", available_check)
                        .await;
                    let state = Self::configure(
                        index,
                        storage,
                        synced_probe,
                        available_probe,
                        context.metrics.registry(),
                        self.devmode,
                    )?;

                    let mut http = HttpServerBuilder::try_from(self.http)?
                        .tracing(tracing)
                        .metrics(context.metrics.registry().clone(), "bombastic_api")
                        .authorizer(authorizer.clone())
                        .configure(move |svc| {
                            let authenticator = authenticator.clone();
                            let swagger_oidc = swagger_oidc.clone();

                            svc.app_data(web::Data::new(state.clone())).configure(move |svc| {
                                server::config(svc, authenticator.clone(), swagger_oidc.clone(), publish_limit);
                                vex::config(svc, authenticator, swagger_oidc, publish_limit);
                            });
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
        synced_probe: Probe,
        available_probe: Probe,
        registry: &Registry,
        devmode: bool,
    ) -> anyhow::Result<Arc<AppState>> {
        let sbom_index =
            block_in_place(|| IndexStore::new(&storage, &index_config, bombastic_index::sbom::Index::new(), registry))?;

        let package_index = block_in_place(|| {
            IndexStore::new(
                &storage,
                &index_config,
                bombastic_index::packages::Index::new(),
                registry,
            )
        })?;

        let vex_index =
            block_in_place(|| IndexStore::new(&storage, &index_config, vexination_index::Index::new(), registry))?;

        let storage = Storage::new(storage.process("bombastic", devmode), registry)?;

        let state = Arc::new(AppState {
            storage,
            sbom_index,
            package_index,
            vex_index,
        });

        let sinker = state.clone();
        let sync_interval = index_config.sync_interval.into();
        tokio::task::spawn(async move {
            loop {
                if sinker.sync_index().await.is_ok() {
                    log::info!("Initial bombastic index synced");
                    break;
                } else {
                    log::warn!("Bombastic index not yet available");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            synced_probe.set(true);
            available_probe.set(true);
            let mut size = 0;

            loop {
                if let Err(e) = sinker.sync_index().await {
                    log::info!("Unable to synchronize bombastic index: {:?}", e);
                }
                let result = sinker.sbom_index.search("", 0, 100, Default::default());
                match result {
                    Ok(found) => {
                        if size != 0 && found.1 == 0 {
                            // index size went to zero, the service should be restarted
                            available_probe.set(false);
                        } else {
                            available_probe.set(true);
                        }
                        size = found.1;
                    }
                    Err(_) => {
                        // error accessing index
                        available_probe.set(false);
                    }
                };
                tokio::time::sleep(sync_interval).await;
            }
        });

        Ok(state)
    }
}

pub(crate) type SbomIndex = IndexStore<bombastic_index::sbom::Index>;
pub(crate) type PackageIndex = IndexStore<bombastic_index::packages::Index>;
pub(crate) type VexIndex = IndexStore<vexination_index::Index>;
pub struct AppState {
    storage: Storage,
    sbom_index: SbomIndex,
    package_index: PackageIndex,
    vex_index: VexIndex,
}

pub(crate) type SharedState = Arc<AppState>;

impl AppState {
    async fn sync_index(&self) -> Result<(), anyhow::Error> {
        let storage = &self.storage;
        self.sbom_index.sync(storage).await?;
        self.package_index.sync(storage).await?;
        Ok(())
    }
}
