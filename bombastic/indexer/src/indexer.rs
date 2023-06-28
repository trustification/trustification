use std::time::Duration;

use bombastic_index::Index;
use futures::pin_mut;
use tokio::select;
use trustification_event_bus::EventBus;
use trustification_index::IndexStore;
use trustification_storage::{EventType, Storage};

pub async fn run(
    mut index: IndexStore<Index>,
    storage: Storage,
    bus: EventBus,
    stored_topic: &str,
    indexed_topic: &str,
    failed_topic: &str,
    sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    // Load initial index from storage.
    // TODO: Stream directly to file
    if let Ok(data) = storage.get_index().await {
        index.reload(&data[..])?;
    }

    let mut interval = tokio::time::interval(sync_interval);
    let mut events = 0;
    let mut writer = Some(index.writer()?);
    let consumer = bus.subscribe("indexer", &[stored_topic]).await?;
    let mut uncommitted_events = Vec::new();
    loop {
        let tick = interval.tick();
        pin_mut!(tick);
        select! {
            event = consumer.next() => match event {
                Ok(Some(event)) => {
                    if let Some(payload) = event.payload() {
                        if let Ok(data) = storage.decode_event(payload) {
                            for data in data.records {
                                if storage.is_index(data.key()) {
                                    log::trace!("It's an index event, ignoring");
                                } else {
                                    match data.event_type() {
                                        EventType::Put => {
                                            let key = data.key();
                                            match storage.get_for_event(&data).await {
                                                Ok((k, data)) => {
                                                    match bombastic_index::SBOM::parse(&data) {
                                                        Ok(doc) => match writer.as_mut().unwrap().add_document(index.index_as_mut(), &k, &doc) {
                                                            Ok(_) => {
                                                                log::trace!("Inserted entry into index");
                                                                bus.send(indexed_topic, key.as_bytes()).await?;
                                                                events += 1;
                                                            }
                                                            Err(e) => {
                                                                let failure = serde_json::json!( {
                                                                    "key": key,
                                                                    "error": e.to_string(),
                                                                }).to_string();
                                                                bus.send(failed_topic, failure.as_bytes()).await?;
                                                                log::warn!("Error inserting entry into index: {:?}", e)
                                                            }
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Error parsing SBOM for key {}: {:?}, ignored", key, e);
                                                        let failure = serde_json::json!( {
                                                                "key": key,
                                                                "error": e.to_string(),
                                                            }).to_string();
                                                        bus.send(failed_topic, failure.as_bytes()).await?;
                                                    }
                                                    }
                                                }
                                                Err(e) => {
                                                    log::warn!("Error retrieving document event data, ignoring (error: {:?})", e);
                                                }
                                            }
                                        },
                                        EventType::Delete => {
                                            let (_, key) = Storage::key_from_event(&data)?;
                                            writer.as_mut().unwrap().delete_document(index.index(), key.as_str());
                                            log::debug!("Deleted entry {key} from index");
                                            events += 1;
                                        }
                                        _ => log::debug!("Non (PUT | DELETE)  event ({:?}), skipping", data),
                                    }
                                }
                            }
                        } else {
                            log::warn!("Error decoding event, skipping");
                        }
                    } else {
                        log::warn!("No event for payload, skipping");
                    }
                    uncommitted_events.push(event);
                }
                Ok(None) => {
                    log::debug!("Polling returned no events, retrying");
                }
                Err(e) => {
                    log::warn!("Error polling for event: {:?}", e);
                }
            },
            _ = tick => {
                if events > 0 {
                    log::trace!("{} new events added, pushing new index to storage", events);
                    match index.snapshot(writer.take().unwrap()) {
                        Ok(data) => {
                            match storage.put_index(&data).await {
                                Ok(_) => {
                                    log::trace!("Index updated successfully");
                                    match consumer.commit(&uncommitted_events[..]).await {
                                        Ok(_) => {
                                            log::trace!("Event committed successfully");
                                            uncommitted_events.clear();
                                        }
                                        Err(e) => {
                                            log::warn!("Error committing event: {:?}", e)
                                        }
                                    }
                                    events = 0;
                                }
                                Err(e) => {
                                    log::warn!("Error updating index: {:?}", e)
                                }
                            }

                            writer.replace(index.writer()?);
                        }
                        Err(e) => {
                            log::warn!("Error taking index snapshot: {:?}", e);
                        }
                    }
                } else {
                    log::trace!("No changes to index");
                }
            }
        }
    }
}
