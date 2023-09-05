use super::Event;
use segment::{
    message::{BatchMessage, Track, User},
    AutoBatcher, Batcher,
};
use serde_json::json;
use tokio::sync::Mutex;

impl From<Event> for BatchMessage {
    fn from(value: Event) -> Self {
        match value {
            Event::ScanSbom { r#type, status_code } => BatchMessage::Track(Track {
                user: User::AnonymousId {
                    anonymous_id: uuid::Uuid::new_v4().to_string(),
                },
                event: "scan_sbom".into(),
                properties: json!({
                    "type": r#type,
                    "status_code": status_code.map(|code|code.as_u16()),
                }),
                ..Default::default()
            }),
        }
    }
}

#[derive(Debug)]
pub struct SegmentTracker {
    batcher: Option<Mutex<AutoBatcher>>,
}

impl SegmentTracker {
    pub fn new(write_key: impl Into<Option<String>>) -> Self {
        let batcher = write_key.into().map(|write_key| {
            let context = Some(json!({
                "library": {
                    "name": "https://github.com/meilisearch/segment",
                }
            }));

            Mutex::new(AutoBatcher::new(
                segment::HttpClient::default(),
                Batcher::new(context),
                write_key,
            ))
        });

        Self { batcher }
    }

    pub async fn track(&self, event: Event) {
        if let Some(batcher) = &self.batcher {
            if let Err(err) = batcher.lock().await.push(event).await {
                // FIXME: track errors with metrics
                log::warn!("Failed to push analytics batch: {err}");
            }
        }
    }

    pub async fn flush(&self) {
        if let Some(batcher) = &self.batcher {
            if let Err(err) = batcher.lock().await.flush().await {
                // FIXME: track errors with metrics
                log::warn!("Failed to flush analytics batch: {err}");
            }
        }
    }
}
