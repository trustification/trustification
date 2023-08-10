use std::sync::Arc;
use std::{future::Future, pin::Pin};

use actix_web::{http::uri::Builder, middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use anyhow::Context;
use futures::future::select_all;
use prometheus::{Registry, TextEncoder};
use tokio::signal;

use crate::tracing::init_tracing;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

const DEFAULT_BIND_ADDR: &str = "[::1]:9010";

/// Infrastructure
#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "Infrastructure")]
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

    let apis = ["/health/live", "/health/ready", "/health/startup", "/metrics"]
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

async fn metrics(metrics: web::Data<Arc<Metrics>>) -> HttpResponse {
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry().gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(data) => HttpResponse::Ok().content_type("text/plain").body(data),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error retrieving metrics: {:?}", e)),
    }
}

#[derive(Default)]
pub struct Infrastructure {
    config: InfrastructureConfig,
    metrics: Arc<Metrics>,
}

impl From<InfrastructureConfig> for Infrastructure {
    fn from(config: InfrastructureConfig) -> Self {
        Self {
            config,
            metrics: Default::default(),
        }
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
            let metrics_registry = self.metrics.clone();
            App::new()
                .wrap(Logger::default())
                .app_data(web::Data::new(metrics_registry))
                .service(web::resource("/").to(index))
                .service(
                    web::scope("/health")
                        .service(web::resource("/live").to(health))
                        .service(web::resource("/ready").to(health))
                        .service(web::resource("/startup").to(health)),
                )
                .service(web::resource("/metrics").to(metrics))
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
        F: FnOnce(Arc<Metrics>) -> Fut,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        init_tracing(id, self.config.enable_tracing.into());
        let main = Box::pin(main(self.metrics.clone())) as Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;
        let runner = Box::pin(self.start_internal().await?);
        let sigint = Box::pin(async { signal::ctrl_c().await.context("termination failed") });

        #[allow(unused_mut)]
        let mut tasks = vec![runner, main, sigint];

        #[cfg(unix)]
        {
            let sigterm = Box::pin(async {
                signal(SignalKind::terminate())?.recv().await;
                Ok(())
            });
            tasks.push(sigterm);
        }

        let (result, _index, _others) = select_all(tasks).await;
        result
    }
}

#[derive(Default)]
pub struct Metrics {
    registry: Registry,
}

impl Metrics {
    pub fn registry(&self) -> &Registry {
        &self.registry
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
