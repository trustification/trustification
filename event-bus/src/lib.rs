//! Traits with required functionality for the event bus used in Bombastic.
use std::fmt::Debug;

#[async_trait::async_trait]
pub trait Event {
    fn topic(&self) -> Result<&str, ()>;
    fn payload(&self) -> Option<&[u8]>;
}

#[async_trait::async_trait]
pub trait EventBus {
    type Consumer<'m>: EventConsumer
    where
        Self: 'm;

    async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<Self::Consumer<'_>, anyhow::Error>;
    async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error>;
    async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error>;
}

#[async_trait::async_trait]
pub trait EventConsumer {
    type Event<'m>: Event
    where
        Self: 'm;
    async fn next<'m>(&'m self) -> Result<Option<Self::Event<'m>>, anyhow::Error>;
    async fn commit<'m>(&'m self, events: &[Self::Event<'m>]) -> Result<(), anyhow::Error>;
}

#[cfg(feature = "kafka")]
pub mod kafka;

#[cfg(feature = "sqs")]
pub mod sqs;
