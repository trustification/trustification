//! Traits with required functionality for the event bus used in Bombastic.
use std::fmt::Debug;

#[async_trait::async_trait]
pub trait Event {
    fn topic(&self) -> Result<Topic, ()>;
    fn payload(&self) -> Option<&[u8]>;
    async fn commit(&self) -> Result<(), anyhow::Error>;
}

#[async_trait::async_trait]
pub trait EventBus {
    type Consumer<'m>: EventConsumer
    where
        Self: 'm;

    async fn subscribe(&self, group: &str, topics: &[Topic]) -> Result<Self::Consumer<'_>, anyhow::Error>;
    async fn create(&self, topics: &[Topic]) -> Result<(), anyhow::Error>;
    async fn send(&self, topic: Topic, data: &[u8]) -> Result<(), anyhow::Error>;
}

#[async_trait::async_trait]
pub trait EventConsumer {
    type Event<'m>: Event
    where
        Self: 'm;
    async fn next<'m>(&'m self) -> Result<Option<Self::Event<'m>>, anyhow::Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum Topic {
    STORED,
    INDEXED,
    FAILED,
}

impl TryFrom<&str> for Topic {
    type Error = ();
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "stored" => Ok(Topic::STORED),
            "indexed" => Ok(Topic::INDEXED),
            "failed" => Ok(Topic::FAILED),
            _ => Err(()),
        }
    }
}

impl AsRef<str> for Topic {
    fn as_ref(&self) -> &str {
        match self {
            Self::STORED => "stored",
            Self::INDEXED => "indexed",
            Self::FAILED => "failed",
        }
    }
}

#[cfg(feature = "kafka")]
pub mod kafka;

#[cfg(feature = "sqs")]
pub mod sqs;
