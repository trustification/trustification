use guac::collector::{emitter::Emitter, Document, DocumentType, FormatType, SourceInformation};
use tokio::select;
use trustification_event_bus::{Event, EventBus, EventConsumer};
use trustification_storage::{EventType, Storage};

pub async fn run<E: EventBus, M: Emitter + Send + Sync>(
    storage: Storage,
    bus: E,
    emitter: M,
    stored_topic: &str,
) -> Result<(), anyhow::Error> {
    let consumer = bus.subscribe("exporter", &[stored_topic]).await?;
    loop {
        select! {
            event = consumer.next() => match event {
                Ok(Some(event)) => {
                    if let Some(payload) = event.payload() {
                        if let Ok(data) = storage.decode_event(&payload) {
                            for data in data.records {
                                if data.event_type() == EventType::Put {
                                    if storage.is_index(data.key()) {
                                        tracing::trace!("It's an index event, ignoring");
                                    } else {
                                        let key = data.key();
                                        match storage.get_for_event(&data).await {
                                            Ok(data) => {
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
                                                        tracing::trace!("Exported SBOM entry!");
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!("Error exporting entry: {:?}", e)
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::debug!("Error retrieving document event data, ignoring (error: {:?})", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!("Polling returned no events, retrying");
                }
                Err(e) => {
                    tracing::warn!("Error polling for event: {:?}", e);
                }
            },
        }
    }
}
