use std::time::Duration;

use futures::pin_mut;
use tokio::select;
use trustification_event_bus::EventBus;
use trustification_index::IndexStore;
use trustification_storage::{EventType, Storage};
use vexination_index::Index;
use tokio::task::block_in_place;

pub async fn run(
    mut index: IndexStore<Index>,
    storage: Storage,
    bus: EventBus,
    stored_topic: &str,
    indexed_topic: &str,
    failed_topic: &str,
    sync_interval: Duration,
) -> Result<(), anyhow::Error> {
    let mut interval = tokio::time::interval(sync_interval);
    let mut writer = block_in_place(|| Some(index.writer().unwrap()));
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
                                if data.event_type() == EventType::Put {
                                    if storage.is_index(data.key()) {
                                        log::trace!("It's an index event, ignoring");
                                    } else {
                                        let key = data.key();
                                        match storage.get_for_event(&data).await {
                                            Ok((_, data)) => {
                                                match serde_json::from_slice::<csaf::Csaf>(&data) {
                                                    Ok(doc) => match block_in_place(|| writer.as_mut().unwrap().add_document(index.index_as_mut(), &doc.document.tracking.id, &doc)) {
                                                        Ok(_) => {
                                                            log::debug!("Inserted entry into index");
                                                            bus.send(indexed_topic, key.as_bytes()).await?;
                                                        }
                                                        Err(e) => {
                                                            log::warn!("Error inserting entry into index: {:?}", e);
                                                            let failure = serde_json::json!( {
                                                                "key": key,
                                                                "error": e.to_string(),
                                                            }).to_string();
                                                            bus.send(failed_topic, failure.as_bytes()).await?;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Error parsing object as CSAF: {:?}", e);
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
                                    }
                                } else {
                                    log::debug!("Non-PUT event ({:?}), skipping", data);
                                }
                            }
                        } else {
                            log::warn!("Error decoding event, skipping");
                        }
                    } else {
                        log::warn!("No event for payload, skipping");
                    }
                    uncommitted_events.push(event);
                },
                Ok(None) => {
                    log::debug!("Polling returned no events, retrying");
                }
                Err(e) => {
                    log::warn!("Error polling for event: {:?}", e);
                }
            },
            _ = tick => {
                if let Some(w) = writer.take() {
                    match block_in_place(|| w.commit()) {
                        Ok(_) => {
                            log::info!("New index committed");
                            match consumer.commit(&uncommitted_events[..]).await {
                                Ok(_) => {
                                    log::trace!("Committed {} events successfully", uncommitted_events.len());
                                    uncommitted_events.clear();
                                }
                                Err(e) => {
                                    log::warn!("Error committing event: {:?}", e)
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Error committing index: {:?}", e);
                        }
                    }
                    writer.replace(block_in_place(|| index.writer().unwrap()));
                }
            }
        }
    }
}
