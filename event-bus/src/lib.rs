#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

use std::fmt::Debug;

pub trait Event {
    type Error: Debug;
    fn payload(&self) -> Option<&[u8]>;
    fn commit(&self) -> Result<(), Self::Error>;
}

pub trait EventBus {
    type Error: Debug;
    type Event<'m>: Event;
    async fn poll<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error>;
}

#[cfg(feature = "kafka")]
pub mod kafka;
