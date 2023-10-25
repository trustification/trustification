use crate::processing::ProcessVisitor;
use sbom_walker::model::metadata::Key;
use sbom_walker::retrieve::RetrievingVisitor;
use sbom_walker::source::{DispatchSource, FileSource, HttpOptions, HttpSource};
use sbom_walker::validation::ValidationVisitor;
use sbom_walker::visitors::send::SendVisitor;
use sbom_walker::walker::Walker;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::MissedTickBehavior;
use tracing::{instrument, log};
use url::Url;
use walker_common::since::Since;
use walker_common::{
    fetcher::{Fetcher, FetcherOptions},
    sender::{self, provider::TokenProvider},
    validate::ValidationOptions,
};

pub struct Options {
    pub source: Url,
    pub target: Url,
    pub keys: Vec<Key>,
    pub provider: Arc<dyn TokenProvider>,
    pub validation_date: Option<SystemTime>,
    pub fix_licenses: bool,
    pub since_file: Option<PathBuf>,
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
        let source: DispatchSource = match self.options.source.to_file_path() {
            Ok(path) => FileSource::new(path, None)?.into(),
            Err(_) => HttpSource {
                url: self.options.source.clone(),
                fetcher: Fetcher::new(FetcherOptions::default()).await?,
                options: HttpOptions {
                    keys: self.options.keys.clone(),
                    since: *since,
                },
            }
            .into(),
        };

        let sender = sender::HttpSender::new(self.options.provider.clone(), sender::Options::default()).await?;

        let storage = SendVisitor {
            url: self.options.target.clone(),
            sender,
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
