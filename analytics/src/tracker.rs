use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Clone, Debug, Default, clap::Args)]
#[command(next_help_heading = "segment.io configuration")]
pub struct AnalyticsConfig {
    /// The segment.io write key. If not present, tracking will be disabled.
    #[cfg(feature = "analytics")]
    #[arg(long = "segment-write-key", env = "SEGMENT_WRITE_KEY")]
    pub write_key: Option<String>,
}

pub type FlusherFut = Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

#[cfg(feature = "tracker")]
pub struct Tracker {
    #[cfg(feature = "analytics")]
    segment: super::segment::SegmentTracker,
}

#[cfg(all(feature = "analytics", feature = "tracker"))]
impl Tracker {
    pub fn new(config: AnalyticsConfig) -> (Arc<Self>, Option<FlusherFut>) {
        let tracker = Arc::new(Self {
            segment: super::segment::SegmentTracker::new(config.write_key),
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

    pub async fn track(&self, event: impl super::TrackingEvent) {
        self.segment.push(event).await;
    }
}

#[cfg(all(not(feature = "analytics"), feature = "tracker"))]
impl Tracker {
    pub fn new(_config: AnalyticsConfig) -> (Arc<Self>, Option<FlusherFut>) {
        (Arc::new(Self {}), None)
    }

    pub async fn track(&self, _event: impl super::TrackingEvent) {}
}
