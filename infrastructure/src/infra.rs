use std::{future::Future, pin::Pin};

use actix_web::{http::uri::Builder, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use futures::future::select_all;

use crate::tracing::init_tracing;

const DEFAULT_BIND_ADDR: &str = "localhost:9010";

/// Infrastructure
#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct InfrastructureConfig {
    /// Enable the infrastructure endpoint
    #[arg(env, long)]
    pub infrastructure_enabled: bool,
    /// Bind addresses of the infrastructure endpoint
    #[arg(long, env, default_value_t = DEFAULT_BIND_ADDR.into())]
    pub infrastructure_bind: String,
    /// Number of workers
    #[arg(long, env, default_value = "1")]
    pub infrastructure_workers: usize,
    /// Enable tracing
    #[arg(long, env)]
    pub enable_tracing: bool,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            infrastructure_enabled: false,
            infrastructure_bind: DEFAULT_BIND_ADDR.into(),
            infrastructure_workers: 1,
            enable_tracing: false,
        }
    }
}

pub async fn index(req: HttpRequest) -> HttpResponse {
    let conn = req.connection_info();

    let apis = ["/health/live", "/health/ready", "/health/startup"]
        .into_iter()
        .filter_map(|api| {
            Builder::new()
                .authority(conn.host())
                .scheme(conn.scheme())
                .path_and_query(api)
                .build()
                .ok()
                .map(|uri| uri.to_string())
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(apis)
}

async fn health() -> impl Responder {
    HttpResponse::Ok()
}

#[derive(Default)]
pub struct Infrastructure {
    config: InfrastructureConfig,
}

impl From<InfrastructureConfig> for Infrastructure {
    fn from(config: InfrastructureConfig) -> Self {
        Self { config }
    }
}

impl Infrastructure {
    /// create a new instance, with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(self) -> anyhow::Result<InfrastructureRunner> {
        Ok(InfrastructureRunner {
            runner: Box::pin(self.start_internal().await?),
        })
    }

    async fn start_internal(self) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>> {
        if !self.config.infrastructure_enabled {
            log::info!("Infrastructure endpoint is disabled");
            return Ok(Box::pin(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await
                }
            }));
        }

        log::info!("Setting up infrastructure endpoint");

        let mut http = HttpServer::new(move || {
            App::new()
                .wrap(Logger::default())
                .service(web::resource("/").to(index))
                .service(
                    web::scope("/health")
                        .service(web::resource("/live").to(health))
                        .service(web::resource("/ready").to(health))
                        .service(web::resource("/startup").to(health)),
                )
        });

        if self.config.infrastructure_workers > 0 {
            http = http.workers(self.config.infrastructure_workers);
        }

        http = http
            .bind(self.config.infrastructure_bind)
            .context("Failed to bind infrastructure endpoint")?;

        Ok(Box::pin(async move {
            log::info!("Running infrastructure endpoint on:");
            for (addr, scheme) in http.addrs_with_scheme() {
                log::info!("   {scheme}://{addr}");
            }
            http.run().await.context("Failed to run infrastructure endpoint")?;
            Ok::<_, anyhow::Error>(())
        }))
    }

    pub async fn run<F, Fut>(self, id: &str, main: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        init_tracing(id, self.config.enable_tracing.into());
        let runner = Box::pin(self.start_internal().await?);
        let main = Box::pin(main()) as Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;
        let (result, _index, _others) = select_all([runner, main]).await;
        result
    }
}

pub struct InfrastructureRunner {
    runner: Pin<Box<dyn Future<Output = anyhow::Result<()>>>>,
}

impl InfrastructureRunner {
    pub async fn run(self) -> anyhow::Result<()> {
        self.runner.await
    }
}
