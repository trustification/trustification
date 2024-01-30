use crate::processing::ProcessVisitor;
use sbom_walker::model::metadata::Key;
use sbom_walker::retrieve::RetrievingVisitor;
use sbom_walker::source::{DispatchSource, FileSource, HttpOptions, HttpSource};
use sbom_walker::validation::ValidationVisitor;
use sbom_walker::walker::Walker;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::MissedTickBehavior;
use tracing::{instrument, log};
use url::Url;
use walker_common::{
    fetcher::{Fetcher, FetcherOptions},
    sender::{self, provider::TokenProvider},
    since::Since,
    validate::ValidationOptions,
};

pub struct Options {
    pub source: String,
    pub target: Url,
    pub keys: Vec<Key>,
    pub provider: Arc<dyn TokenProvider>,
    pub validation_date: Option<SystemTime>,
    pub fix_licenses: bool,
    pub since_file: Option<PathBuf>,
    pub retries: usize,
    pub retry_delay: Option<Duration>,
    pub additional_root_certificates: Vec<PathBuf>,
}

pub struct Scanner {
    options: Options,
}

impl Scanner {
    pub fn new(options: Options) -> Self {
        Self { options }
    }

    pub async fn run(self, interval: Duration) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            if let Err(err) = self.run_once().await {
                log::warn!("Failed to perform sync: {err}");
            }
            interval.tick().await;
        }
    }

    #[instrument(skip(self))]
    pub async fn run_once(&self) -> anyhow::Result<()> {
        let since = Since::new(None::<SystemTime>, self.options.since_file.clone(), Default::default())?;
        let source: DispatchSource = match Url::parse(&self.options.source) {
            Ok(url) => HttpSource {
                url,
                fetcher: Fetcher::new(FetcherOptions::default()).await?,
                options: HttpOptions {
                    keys: self.options.keys.clone(),
                    since: *since,
                },
            }
            .into(),
            Err(_) => FileSource::new(&self.options.source, None)?.into(),
        };

        let sender = sender::HttpSender::new(
            self.options.provider.clone(),
            sender::Options {
                additional_root_certificates: self.options.additional_root_certificates.clone(),
                ..sender::Options::default()
            },
        )
        .await?;

        let storage = walker_extras::visitors::SendVisitor {
            url: self.options.target.clone(),
            sender,
            retries: self.options.retries,
            retry_delay: self.options.retry_delay,
        };

        let process = ProcessVisitor {
            enabled: self.options.fix_licenses,
            next: storage,
        };

        let validation = ValidationVisitor::new(process).with_options(ValidationOptions {
            validation_date: self.options.validation_date,
        });

        let walker = Walker::new(source.clone());
        walker.walk(RetrievingVisitor::new(source.clone(), validation)).await?;

        since.store()?;

        Ok(())
    }
}
