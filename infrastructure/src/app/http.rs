use crate::app::{new_app, AppOptions};
use actix_cors::Cors;
use actix_tls::{accept::openssl::reexports::SslAcceptor, connect::openssl::reexports::SslMethod};
use actix_web::web::JsonConfig;
use actix_web::{web, web::ServiceConfig, HttpServer};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use anyhow::{anyhow, Context};
use openssl::ssl::SslFiletype;
use prometheus::Registry;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use trustification_auth::{authenticator::Authenticator, authorizer::Authorizer};

const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x1)), 8080);

#[derive(Clone, Debug, clap::Args)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "HTTP endpoint")]
pub struct HttpServerConfig {
    /// The number of worker threads, defaults to zero, which falls back to the number of cores.
    #[arg(id = "http-server-workers", long, env = "HTTP_SERVER_WORKERS")]
    pub workers: usize,

    /// The bind address
    #[arg(
        id = "http-server-bind",
        long,
        env,
        default_value = "[::1]:8080",
        env = "HTTP_SERVER_BIND_ADDR"
    )]
    pub bind_addr: String,

    /// The overall request limit
    #[arg(
        id = "http-server-request-limit",
        long,
        env,
        default_value = "256KiB",
        env = "HTTP_SERVER_REQUEST_LIMIT"
    )]
    pub request_limit: bytesize::ByteSize,

    /// The JSON request limit
    #[arg(
        id = "http-server-json-limit",
        long,
        env,
        default_value = "2MiB",
        env = "HTTP_SERVER_JSON_LIMIT"
    )]
    pub json_limit: bytesize::ByteSize,

    /// Enable TLS
    #[arg(id = "http-server-tls-enabled", long, env = "HTTP_SERVER_TLS_ENABLED")]
    pub tls_enabled: bool,

    /// The path to the TLS key file in PEM format
    #[arg(id = "http-server-tls-key-file", long, env = "HTTP_SERVER_TLS_KEY_FILE")]
    pub tls_key_file: Option<PathBuf>,

    /// The path to the TLS certificate in PEM format
    #[arg(
        id = "http-server-tls-certificate-file",
        long,
        env = "HTTP_SERVER_TLS_CERTIFICATE_FILE"
    )]
    pub tls_certificate_file: Option<PathBuf>,
}

impl TryFrom<HttpServerConfig> for HttpServerBuilder {
    type Error = anyhow::Error;

    fn try_from(value: HttpServerConfig) -> Result<Self, Self::Error> {
        let result = HttpServerBuilder::new().workers(value.workers);

        let addr = SocketAddr::from_str(&value.bind_addr).context("parse bind address")?;

        let result = match value.tls_enabled {
            true => result.bind(addr),
            false => result.bind_tls(
                addr,
                value.tls_key_file.ok_or_else(|| {
                    anyhow!("TLS enabled but no key file configured (use --http-server-tls-key-file)")
                })?,
                value.tls_certificate_file.ok_or_else(|| {
                    anyhow!("TLS enabled but no certificate file configured (use --http-server-tls-certificate-file)")
                })?,
            ),
        };

        let result = result
            .request_limit(value.request_limit.0 as _)
            .json_limit(value.json_limit.0 as _);

        Ok(result)
    }
}

pub type ConfiguratorFn = dyn Fn(&mut ServiceConfig) + Send + Sync;

pub struct HttpServerBuilder {
    configurator: Option<Arc<ConfiguratorFn>>,
    bind: Bind,
    metrics_factory: Option<Arc<dyn Fn() -> anyhow::Result<PrometheusMetrics> + Send + Sync>>,
    cors_factory: Option<Arc<dyn Fn() -> Cors + Send + Sync>>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Option<Authorizer>,

    workers: usize,
    json_limit: Option<usize>,
    request_limit: Option<usize>,
}

pub enum Bind {
    Listener(TcpListener),
    Plain(SocketAddr),
    Tls {
        address: SocketAddr,
        certificate: PathBuf,
        key: PathBuf,
    },
}

impl Default for HttpServerBuilder {
    fn default() -> Self {
        HttpServerBuilder::new()
    }
}

impl HttpServerBuilder {
    pub fn new() -> Self {
        Self {
            configurator: None,
            bind: Bind::Plain(DEFAULT_ADDR),
            metrics_factory: None,
            cors_factory: Some(Arc::new(Cors::permissive)),
            authenticator: None,
            authorizer: None,
            workers: 0,
            json_limit: None,
            request_limit: None,
        }
    }

    /// Set a custom CORS factory.
    ///
    /// The default is [`Cors::permissive`].
    pub fn cors<F>(mut self, cors_factory: F) -> Self
    where
        F: Fn() -> Cors + Send + Sync + 'static,
    {
        self.cors_factory = Some(Arc::new(cors_factory));
        self
    }

    pub fn cors_disabled(mut self) -> Self {
        self.cors_factory = None;
        self
    }

    pub fn default_authenticator(mut self, authenticator: Option<Arc<Authenticator>>) -> Self {
        self.authenticator = authenticator;
        self
    }

    pub fn authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    pub fn configure<F>(mut self, configurator: F) -> Self
    where
        F: Fn(&mut ServiceConfig) + Send + Sync + 'static,
    {
        self.configurator = Some(Arc::new(configurator));
        self
    }

    pub fn metrics(mut self, registry: impl Into<Registry>, namespace: impl AsRef<str>) -> Self {
        let metrics = PrometheusMetricsBuilder::new(namespace.as_ref())
            .registry(registry.into())
            .build();

        self.metrics_factory = Some(Arc::new(move || {
            metrics.as_ref().map(|r| r.clone()).map_err(|err| anyhow!("{err}"))
        }));

        self
    }

    pub fn metrics_factory<F>(mut self, metrics_factory: F) -> Self
    where
        F: Fn() -> Result<PrometheusMetrics, Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
    {
        self.metrics_factory = Some(Arc::new(move || {
            (metrics_factory)().map_err(|err| anyhow!("Failed to create prometheus registry: {err}"))
        }));
        self
    }

    pub fn listen(mut self, listener: TcpListener) -> Self {
        self.bind = Bind::Listener(listener);
        self
    }

    pub fn bind(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.bind = Bind::Plain(addr.into());
        self
    }

    pub fn bind_tls(
        mut self,
        addr: impl Into<SocketAddr>,
        key: impl Into<PathBuf>,
        certificate: impl Into<PathBuf>,
    ) -> Self {
        self.bind = Bind::Tls {
            address: addr.into(),
            certificate: certificate.into(),
            key: key.into(),
        };
        self
    }

    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }

    pub fn json_limit(mut self, json_limit: usize) -> Self {
        self.json_limit = Some(json_limit);
        self
    }

    pub fn request_limit(mut self, request_limit: usize) -> Self {
        self.request_limit = Some(request_limit);
        self
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let metrics = self.metrics_factory.as_ref().map(|factory| (factory)()).transpose()?;

        let mut http = HttpServer::new(move || {
            let config = self.configurator.clone();

            let cors = self.cors_factory.as_ref().map(|factory| (factory)());

            let mut json = JsonConfig::default();
            if let Some(limit) = self.json_limit {
                json = json.limit(limit);
            }

            let mut app = new_app(AppOptions {
                cors,
                metrics: metrics.clone(),
                authenticator: self.authenticator.clone(),
                authorizer: self.authorizer.clone().unwrap_or_else(|| Authorizer::new(None)),
            });

            // configure payload limit

            if let Some(limit) = self.request_limit {
                app = app.app_data(web::PayloadConfig::new(limit));
            }

            app.app_data(json).configure(|svc| {
                if let Some(config) = config {
                    config(svc);
                }
            })
        });

        if self.workers > 0 {
            http = http.workers(self.workers);
        }

        match self.bind {
            Bind::Listener(listener) => {
                log::info!("Binding to provided listener: {listener:?}");
                http = http.listen(listener).context("Binding to listener")?;
            }
            Bind::Plain(addr) => {
                log::info!("Binding to (plain): {addr}");

                http = http.bind(addr)?;
            }
            Bind::Tls {
                address,
                key,
                certificate,
            } => {
                log::info!("Binding to (TLS): {address}");

                let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
                acceptor.set_certificate_chain_file(certificate)?;
                acceptor.set_private_key_file(key, SslFiletype::PEM)?;

                http = http.bind_openssl(address, acceptor)?;
            }
        }

        Ok(http.run().await?)
    }
}
