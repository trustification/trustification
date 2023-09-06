use serde_json::Value;
use uuid::Uuid;

#[cfg(feature = "tracker")]
mod tracker;

#[cfg(feature = "tracker")]
pub use tracker::*;

#[cfg(feature = "analytics")]
mod segment;

pub enum User<'a> {
    /// We know that's a user, but we don't know who it is.
    ///
    /// The difference to [`User::Unknown`] is, that we know it's a specific user, we just don't
    /// know how it is. In the case of "unknown", it could be a different user every time.
    Anonymous(Uuid),
    /// We know exactly who it is
    Known(&'a str),
    /// We don't know anything about the user
    Unknown,
}

pub trait TrackingEvent {
    /// The name of the event
    fn name(&self) -> &str;

    /// The user associated with the event
    fn user(&self) -> &User {
        &User::Unknown
    }

    /// Additional payload
    fn payload(&self) -> Value {
        Default::default()
    }
}
