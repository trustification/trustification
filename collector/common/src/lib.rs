use anyhow::Context;
use async_trait::async_trait;
use collectorist_client::{CollectorConfig, CollectoristClient, Interest, RegisterResponse};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use trustification_infrastructure::health::Check;
use url::Url;

#[async_trait]
pub trait CollectorStateHandler: Send + Sync + 'static {
    async fn registered(&self, response: RegisterResponse);
    async fn unregistered(&self);
}

#[async_trait]
impl<T> CollectorStateHandler for Arc<T>
where
    T: CollectorStateHandler,
{
    async fn registered(&self, response: RegisterResponse) {
        self.as_ref().registered(response).await
    }

    async fn unregistered(&self) {
        self.as_ref().unregistered().await
    }
}

pub struct FnCollectorStateHandler<R, RFut, U, UFut>
where
    R: Fn(RegisterResponse) -> RFut + Send + Sync,
    RFut: Future<Output = ()> + Send + Sync,
    U: Fn() -> UFut + Send + Sync,
    UFut: Future<Output = ()> + Send + Sync,
{
    registered: R,
    unregistered: U,
}

#[async_trait]
impl<R, RFut, U, UFut> CollectorStateHandler for FnCollectorStateHandler<R, RFut, U, UFut>
where
    R: Fn(RegisterResponse) -> RFut + Send + Sync + 'static,
    RFut: Future<Output = ()> + Send + Sync + 'static,
    U: Fn() -> UFut + Send + Sync + 'static,
    UFut: Future<Output = ()> + Send + Sync + 'static,
{
    async fn registered(&self, response: RegisterResponse) {
        (self.registered)(response).await
    }

    async fn unregistered(&self) {
        (self.unregistered)().await
    }
}

#[derive(Clone, Debug)]
pub struct CollectorState {
    addr: Arc<RwLock<Option<SocketAddr>>>,
    connected: Arc<AtomicBool>,
}

impl CollectorState {
    pub async fn set_addr(&self, addr: SocketAddr) {
        *self.addr.write().await = Some(addr);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn deregister(&self) {}
}

#[async_trait]
impl Check for CollectorState {
    type Error = &'static str;

    async fn run(&self) -> Result<(), Self::Error> {
        match self.is_connected() {
            true => Ok(()),
            false => Err("Not connected to collectorist"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegistrationConfig {
    pub cadence: Duration,
    pub interests: Vec<Interest>,
}

pub struct CollectorRegistration<H>
where
    H: CollectorStateHandler,
{
    config: RegistrationConfig,
    state: CollectorState,
    client: CollectoristClient,
    handler: Option<H>,
}

impl<H> CollectorRegistration<H>
where
    H: CollectorStateHandler,
{
    pub fn new(client: CollectoristClient, config: RegistrationConfig, handler: H) -> Self {
        Self {
            state: CollectorState {
                connected: Default::default(),
                addr: Default::default(),
            },
            config,
            client,
            handler: Some(handler),
        }
    }

    pub fn run(self, advertise: Option<Url>) -> (impl Future<Output = anyhow::Result<()>>, CollectorState) {
        let state = self.state.clone();

        let runner = async move {
            log::info!("collectorist at {}", self.client.register_collector_url());
            log::info!("Starting collectorist loop - advertise: {advertise:?}");

            loop {
                if let Some(addr) = *self.state.addr.read().await {
                    if !self.state.connected.load(Ordering::Relaxed) {
                        let url = match &advertise {
                            Some(url) => url.clone(),
                            None => Url::parse(&format!("http://{addr}/api/v1/"))
                                .context("Failed to build advertisement URL")?,
                        };
                        log::info!(
                            "registering with collectorist at {} with callback={}",
                            self.client.register_collector_url(),
                            url
                        );
                        match self
                            .client
                            .register_collector(CollectorConfig {
                                url,
                                cadence: self.config.cadence,
                                interests: self.config.interests.clone(),
                            })
                            .await
                        {
                            Ok(response) => {
                                if let Some(handler) = &self.handler {
                                    handler.registered(response).await;
                                }
                                self.state.connected.store(true, Ordering::Relaxed);
                                log::info!("successfully registered with collectorist")
                            }
                            Err(e) => {
                                log::warn!("failed to register with collectorist: {}", e)
                            }
                        }
                    }
                }
                sleep(Duration::from_secs(10)).await;
            }
        };

        (runner, state)
    }

    pub async fn deregister(&mut self) {
        if let Some(handler) = self.handler.take() {
            match self.client.deregister_collector().await {
                Ok(()) => {
                    log::info!("deregistered with collectorist");
                }
                Err(err) => {
                    log::warn!("failed to deregister with collectorist: {err}");
                }
            }

            self.state.connected.store(false, Ordering::Relaxed);
            handler.unregistered().await;
        }
    }
}

impl<H> Drop for CollectorRegistration<H>
where
    H: CollectorStateHandler,
{
    fn drop(&mut self) {
        log::info!("Unregistering from collectorist");
        futures_executor::block_on(self.deregister())
    }
}
