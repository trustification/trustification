#[derive(Clone, Debug, Default, clap::Args)]
#[command(next_help_heading = "segment.io configuration")]
pub struct AnalyticsConfig {
    /// The segment.io write key. If not present, tracking will be disabled.
    #[cfg(feature = "analytics")]
    #[arg(long = "segment-write-key", env = "SEGMENT_WRITE_KEY")]
    pub write_key: Option<String>,
}
