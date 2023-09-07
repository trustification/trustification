use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, clap::Args)]
#[command(next_help_heading = "segment.io configuration")]
pub struct AnalyticsConfig {
    /// The segment.io write key. If not present, tracking will be disabled.
    #[arg(long = "segment-write-key", env = "SEGMENT_WRITE_KEY")]
    pub write_key: Option<String>,

    /// A period on how often non-full batches will be flushed.
    #[arg(
        long = "segment-flusher-period",
        env = "SEGMENT_FLUSHER_PERIOD",
        default_value = "15s"
    )]
    pub flusher_period: humantime::Duration,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            write_key: None,
            flusher_period: Duration::from_secs(15).into(),
        }
    }
}

pub type FlusherFut = Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

pub struct Tracker {
    segment: Option<super::segment::SegmentTracker>,
}

impl Tracker {
    pub fn new(config: AnalyticsConfig) -> (Arc<Self>, Option<FlusherFut>) {
        match config.write_key {
            Some(write_key) => {
                let segment = super::segment::SegmentTracker::new(write_key);
                let tracker = Arc::new(Self { segment: Some(segment) });

                let period = std::time::Duration::from_secs(10);

                let flusher = {
                    let tracker = tracker.clone();
                    Box::pin(async move {
                        log::info!("Running analytics flusher: {period:?}");

                        let mut interval = tokio::time::interval(period);
                        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        loop {
                            interval.tick().await;
                            log::info!("Flushing analytics batcher");
                            if let Some(segment) = &tracker.segment {
                                segment.flush().await;
                            }
                        }
                    })
                };
                (tracker, Some(flusher))
            }
            None => (Arc::new(Tracker { segment: None }), None),
        }
    }

    pub async fn track(&self, event: impl super::TrackingEvent) {
        if let Some(segment) = &self.segment {
            segment.push(event).await;
        }
    }
}
