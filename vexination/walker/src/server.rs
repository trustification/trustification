use std::{net::SocketAddr, sync::Arc, time::Duration};

use csaf_walker::{
    fetcher::Fetcher,
    retrieve::RetrievingVisitor,
    source::{FileSource, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

pub async fn run(
    workers: usize,
    source: url::Url,
    sink: url::Url,
    options: ValidationOptions,
) -> Result<(), anyhow::Error> {
    let fetcher = Fetcher::new(Default::default()).await?;

    let validation = ValidationVisitor::new(|advisory: Result<ValidatedAdvisory, ValidationError>| {
        let sink = sink.clone();
        async move {
            match advisory {
                Ok(ValidatedAdvisory { retrieved }) => {
                    let data = retrieved.data;
                    match serde_json::from_slice::<csaf::Csaf>(&data) {
                        Ok(doc) => match reqwest::Client::new().post(sink).json(&doc).send().await {
                            Ok(_) => {
                                log::info!(
                                    "VEX ({}) of size {} stored successfully",
                                    doc.document.tracking.id,
                                    &data[..].len()
                                );
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
