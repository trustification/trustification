use guac::collector::{emitter::Emitter, Document, DocumentType, EncodingType, FormatType, SourceInformation};
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
                                if data.event_type() == EventType::Put && storage.is_relevant(data.key()) {
                                    match storage.get_for_event(&data, false).await {
                                        Ok(res) => {
                                            let document = Document {
                                                blob: res.data,
                                                r#type: DocumentType::UNKNOWN,
                                                format: FormatType::UNKNOWN,
                                                encoding: EncodingType::from(res.encoding.clone()),
                                                source_information: SourceInformation {
                                                    collector: "S3Collector".into(),
                                                    source: res.key.to_string(),
                                                },
                                            };
                                            match emitter.publish(document).await {
                                                Ok(_) => {
                                                    log::info!("Successfully exported the document {} encoded as {}", res.key, res.encoding.unwrap_or("None".to_string()));
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
