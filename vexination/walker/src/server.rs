use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

pub async fn run(storage: Storage, source: url::Url, options: ValidationOptions) -> Result<(), anyhow::Error> {
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

                            let mut annotations = std::collections::HashMap::new();
                            if let Some(sha256) = &retrieved.sha256 {
                                annotations.insert("sha256", sha256.expected.as_str());
                            }

                            if let Some(sha512) = &retrieved.sha512 {
                                annotations.insert("sha512", sha512.expected.as_str());
                            }

                            match storage.put_slice(&key, annotations, "application/json", &data).await {
                                Ok(_) => {
                                    let msg = format!("VEX ({}) of size {} stored successfully", key, &data[..].len());
                                    tracing::info!(msg);
                                }
                                Err(e) => {
                                    let msg = format!("(Skipped) Error storing VEX: {:?}", e);
                                    tracing::info!(msg);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("(Ignored) Error parsing advisory to retrieve ID: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Ignoring advisory: {:?}", e);
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
        let source = HttpSource { url: source, fetcher };
        Walker::new(source.clone())
            .walk(RetrievingVisitor::new(source.clone(), validation))
            .await?;
    }

    Ok(())
}
