#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

pub trait Event {
    type Error;
    fn payload(&self) -> Option<&[u8]>;
    fn commit(&self) -> Result<(), Self::Error>;
}

pub trait EventBus {
    type Error;
    type Event<'m>;
    async fn poll<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error>;
}

#[cfg(feature = "kafka")]
pub mod kafka;
