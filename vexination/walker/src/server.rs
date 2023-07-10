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
use trustification_storage::Storage;

pub async fn run(
    workers: usize,
    storage: Storage,
    source: url::Url,
    options: ValidationOptions,
) -> Result<(), anyhow::Error> {
    let fetcher = Fetcher::new(Default::default()).await?;
    let storage = Arc::new(storage);

    let validation = ValidationVisitor::new(move |advisory: Result<ValidatedAdvisory, ValidationError>| {
        let storage = storage.clone();
        async move {
            match advisory {
                Ok(ValidatedAdvisory { retrieved }) => {
                    let data = retrieved.data;
                    match serde_json::from_slice::<csaf::Csaf>(&data) {
                        Ok(doc) => {
                            let key = doc.document.tracking.id;
                            match storage.put_json_slice(&key, &data).await {
                                Ok(_) => {
                                    let msg = format!("VEX ({}) of size {} stored successfully", key, &data[..].len());
                                    log::info!("{}", msg);
                                }
                                Err(e) => {
                                    let msg = format!("(Skipped) Error storing VEX: {:?}", e);
                                    log::info!("{}", msg);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("(Ignored) Error parsing advisory to retrieve ID: {:?}", e);
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
        let source = FileSource::new(path)?;
        Walker::new(source.clone())
            .walk(RetrievingVisitor::new(source.clone(), validation))
            .await?;
    } else {
        log::info!("Walking VEX docs: source='{source}' workers={workers}");
        let source = HttpSource { url: source, fetcher };
        Walker::new(source.clone())
            .walk_parallel(workers, RetrievingVisitor::new(source.clone(), validation))
            .await?;
    }

    Ok(())
}
