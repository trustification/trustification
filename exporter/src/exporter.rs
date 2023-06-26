use guac::collector::{emitter::Emitter, Document, DocumentType, FormatType, SourceInformation};
use tokio::select;
use trustification_event_bus::EventBus;
use trustification_storage::{EventType, Storage};

pub async fn run<M: Emitter + Send + Sync>(
    storage: Storage,
    bus: EventBus,
    emitter: M,
    stored_topic: &str,
) -> Result<(), anyhow::Error> {
    let consumer = bus.subscribe("exporter", &[stored_topic]).await?;
    loop {
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
                                                let document = Document {
                                                    blob: data,
                                                    r#type: DocumentType::UNKNOWN,
                                                    format: FormatType::UNKNOWN,
                                                    source_information: SourceInformation {
                                                        collector: "S3Collector".into(),
                                                        source: key.to_string(),
                                                    },
                                                };
                                                match emitter.publish(document).await {
                                                    Ok(_) => {
                                                        log::trace!("Exported SBOM entry!");
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Error exporting entry: {:?}", e)
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!("Error retrieving document event data, ignoring (error: {:?})", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    log::debug!("Polling returned no events, retrying");
                }
                Err(e) => {
                    log::warn!("Error polling for event: {:?}", e);
                }
            },
        }
    }
}
