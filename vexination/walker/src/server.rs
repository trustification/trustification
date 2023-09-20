use std::{net::SocketAddr, sync::Arc, time::Duration};

use csaf_walker::{
    fetcher::Fetcher,
    retrieve::RetrievingVisitor,
    source::{FileSource, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use trustification_auth::client::TokenInjector;
use trustification_auth::client::TokenProvider;

pub async fn run(
    workers: usize,
    source: url::Url,
    sink: url::Url,
    provider: Arc<dyn TokenProvider>,
    options: ValidationOptions,
) -> Result<(), anyhow::Error> {
    let fetcher = Fetcher::new(Default::default()).await?;
    let client = Arc::new(reqwest::Client::new());

    let validation = ValidationVisitor::new(|advisory: Result<ValidatedAdvisory, ValidationError>| {
        let sink = sink.clone();
        let provider = provider.clone();
        let client = client.clone();
        async move {
            match advisory {
                Ok(ValidatedAdvisory { retrieved }) => {
                    let data = retrieved.data;
                    match serde_json::from_slice::<csaf::Csaf>(&data) {
                        Ok(doc) => match client
                            .post(sink)
                            .json(&doc)
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
                                log::warn!("(Skipped) Error storing VEX: {}", r.status());
                            }
                            Err(e) => {
                                log::warn!("(Skipped) Error storing VEX: {e:?}");
                            }
                        },
                        Err(e) => {
                            log::warn!("(Ignored) Error parsing advisory to retrieve ID: {e:?}");
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Ignoring advisory: {:?}", e);
                }
            }
            Ok::<_, anyhow::Error>(())
        }
    })
    .with_options(options);

    if let Ok(path) = source.to_file_path() {
        let source = FileSource::new(path, None)?;
        Walker::new(source.clone())
            .walk(RetrievingVisitor::new(source.clone(), validation))
            .await?;
    } else {
        log::info!("Walking VEX docs: source='{source}' workers={workers}");
        let source = HttpSource {
            url: source,
            fetcher,
            options: Default::default(),
        };
        Walker::new(source.clone())
            .walk_parallel(workers, RetrievingVisitor::new(source.clone(), validation))
            .await?;
    }

    Ok(())
}
