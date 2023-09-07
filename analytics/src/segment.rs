use crate::TrackingEvent;
use segment::{
    message::{BatchMessage, Track, User},
    AutoBatcher, Batcher,
};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

pub trait IntoMessage {
    fn into_message(self) -> BatchMessage;
}

fn convert_user(user: &super::User) -> User {
    match user {
        super::User::Unknown => User::AnonymousId {
            anonymous_id: Uuid::new_v4().to_string(),
        },
        super::User::Anonymous(id) => User::AnonymousId {
            anonymous_id: id.to_string(),
        },
        super::User::Known(id) => User::UserId {
            user_id: id.to_string(),
        },
    }
}

impl<T> IntoMessage for T
where
    T: TrackingEvent,
{
    fn into_message(self) -> BatchMessage {
        BatchMessage::Track(Track {
            event: self.name().to_string(),
            user: convert_user(self.user()),
            properties: self.payload(),
            ..Default::default()
        })
    }
}

#[derive(Debug)]
pub struct SegmentTracker {
    batcher: Mutex<AutoBatcher>,
}

impl SegmentTracker {
    pub fn new(write_key: impl Into<String>) -> Self {
        let context = Some(json!({
            "library": {
                "name": "https://github.com/meilisearch/segment",
            }
        }));

        let batcher = Mutex::new(AutoBatcher::new(
            segment::HttpClient::default(),
            Batcher::new(context),
            write_key.into(),
        ));

        Self { batcher }
    }

    pub async fn push(&self, event: impl IntoMessage) {
        if let Err(err) = self.batcher.lock().await.push(event.into_message()).await {
            // FIXME: track errors with metrics
            log::warn!("Failed to push analytics batch: {err}");
        }
    }

    pub async fn flush(&self) {
        if let Err(err) = self.batcher.lock().await.flush().await {
            // FIXME: track errors with metrics
            log::warn!("Failed to flush analytics batch: {err}");
        }
    }
}
