use std::path::PathBuf;
use std::time::SystemTime;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use csaf_walker::{
    discover::DiscoveredAdvisory,
    retrieve::{RetrievedAdvisory, RetrievingVisitor},
    source::{FileSource, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    walker::Walker,
};
use reqwest::{header, StatusCode};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use trustification_auth::client::{TokenInjector, TokenProvider};
use url::Url;
use walker_common::utils::url::Urlify;
use walker_common::{
    fetcher::{Fetcher, FetcherOptions},
    since::Since,
    validate::ValidationOptions,
};

pub async fn run(
    workers: usize,
    source: String,
    sink: Url,
    provider: Arc<dyn TokenProvider>,
    options: ValidationOptions,
    ignore_distributions: Vec<Url>,
    since_file: Option<PathBuf>,
) -> Result<(), anyhow::Error> {
    let fetcher = Fetcher::new(Default::default()).await?;
    let client = Arc::new(reqwest::Client::new());

    let validation = ValidationVisitor::new(|advisory: Result<ValidatedAdvisory, ValidationError>| {
        let sink = sink.clone();
        let provider = provider.clone();
        let client = client.clone();
        async move {
            match advisory {
                Ok(ValidatedAdvisory {
                    retrieved:
                        RetrievedAdvisory {
                            data,
                            discovered: DiscoveredAdvisory { url, .. },
                            ..
                        },
                }) => {
                    let name = url.path_segments().and_then(|s| s.last()).unwrap_or_else(|| url.path());
                    match serde_json::from_slice::<csaf::Csaf>(&data) {
                        Ok(doc) => match client
                            .post(sink)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(data.clone())
                            .inject_token(&provider)
                            .await
                            .unwrap()
                            .send()
                            .await
                        {
                            Ok(r) if r.status() == StatusCode::CREATED => {
                                log::info!(
                                    "VEX ({}) of size {} stored successfully",
                                    doc.document.tracking.id,
                                    &data[..].len()
                                );
                            }
                            Ok(r) => {
                                log::warn!("(Skipped) {name}: Error storing VEX: {}", r.status());
                            }
                            Err(e) => {
                                log::warn!("(Skipped) {name}: Error storing VEX: {e:?}");
                            }
                        },
                        Err(e) => {
                            log::warn!("(Ignored) {name}: Error parsing advisory to retrieve ID: {e:?}");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Ignoring advisory {}: {:?}", e.url(), e);
                }
            }
            Ok::<_, anyhow::Error>(())
        }
    })
    .with_options(options);

    if let Ok(url) = Url::parse(&source) {
        let since = Since::new(None::<SystemTime>, since_file, Default::default())?;
        log::info!("Walking VEX docs: source='{source}' workers={workers}");
        let source = HttpSource {
            url,
            fetcher,
            options: csaf_walker::source::HttpOptions { since: *since },
        };
        Walker::new(source.clone())
            .with_distribution_filter(Box::new(move |distribution| {
                !ignore_distributions.contains(&distribution.directory_url)
            }))
            .walk_parallel(workers, RetrievingVisitor::new(source.clone(), validation))
            .await?;

        since.store()?;
    } else {
        log::info!("Walking VEX docs: path='{source}' workers={workers}");
        let source = FileSource::new(source, None)?;
        Walker::new(source.clone())
            .with_distribution_filter(Box::new(move |distribution| {
                !ignore_distributions.contains(&distribution.directory_url)
            }))
            .walk(RetrievingVisitor::new(source.clone(), validation))
            .await?;
    }

    Ok(())
}
