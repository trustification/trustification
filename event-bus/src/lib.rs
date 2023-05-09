//! Traits with required functionality for the event bus used in Bombastic.
use std::error::Error;
use std::fmt::Debug;

pub trait Event {
    type Error: Debug;
    fn topic(&self) -> Result<Topic, ()>;
    fn payload(&self) -> Option<&[u8]>;
    fn commit(&self) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
pub trait EventBus {
    type Error: Error + Send + Sync + 'static;
    type Consumer: EventConsumer;

    fn subscribe(&self, group: &str, topics: &[Topic]) -> Result<Self::Consumer, Self::Error>;
    async fn create(&self, topics: &[Topic]) -> Result<(), Self::Error>;
    async fn send(&self, topic: Topic, data: &[u8]) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
pub trait EventConsumer {
    type Error: Error + Send + Sync;
    type Event<'m>: Event
    where
        Self: 'm;
    async fn next<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error>;
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
