use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

mod config;
#[cfg(feature = "analytics")]
mod segment;

pub use config::*;

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

pub struct Tracker {
    #[cfg(feature = "analytics")]
    segment: segment::SegmentTracker,
}

pub type FlusherFut = Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

#[cfg(feature = "analytics")]
impl Tracker {
    pub fn new(config: AnalyticsConfig) -> (Arc<Self>, Option<FlusherFut>) {
        let tracker = Arc::new(Self {
            segment: segment::SegmentTracker::new(config.write_key),
        });

        let period = std::time::Duration::from_secs(10);
        log::info!("Running analytics flusher: {period:?}");
        let flusher = {
            let tracker = tracker.clone();
            Box::pin(async move {
                let mut interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    log::info!("Flushing analytics batcher");
                    tracker.segment.flush().await;
                }
            })
        };

        (tracker, Some(flusher))
    }

    pub async fn track(&self, event: impl TrackingEvent) {
        self.segment.push(event).await;
    }
}

#[cfg(not(feature = "analytics"))]
impl Tracker {
    pub fn new(_config: AnalyticsConfig) -> (Arc<Self>, Option<FlusherFut>) {
        (Arc::new(Self {}), None)
    }

    pub async fn track(&self, _event: impl TrackingEvent) {}
}
