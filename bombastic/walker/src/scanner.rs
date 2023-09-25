use std::time::Duration;
use tokio::time::MissedTickBehavior;
use tracing::instrument;
use url::Url;

pub struct Options {
    pub source: Url,
    pub key: Option,
}

pub struct Scanner {}

impl Scanner {
    #[instrument(skip(self))]
    pub async fn run_once(&self) {}

    pub async fn run(self, interval: Duration) {
        let mut interval = tokio::time::interval(interval.into());
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            self.run_once().await;
            interval.tick().await;
        }
    }
}
