use core::fmt;
use std::time::Duration;

use futures::pin_mut;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::block_in_place;
use tokio::time::Instant;
use tokio::{select, sync::Mutex};
use trustification_event_bus::{Error as BusError, EventBus};
use trustification_index::{IndexStore, IndexWriter, WriteIndex};
use trustification_storage::ContinuationToken;
use trustification_storage::{EventType, Storage};

pub mod actix;

#[derive(Clone, Debug)]
pub enum IndexerStatus {
    Running,
    Reindexing { progress: usize },
    Failed { error: String },
}

pub enum IndexerCommand {
    Reindex,
}

#[derive(clap::ValueEnum, Default, Clone, Debug, PartialEq)]
pub enum ReindexMode {
    #[clap(name = "always")]
    Always,
    #[default]
    #[clap(name = "on-failure")]
    OnFailure,
    #[clap(name = "never")]
    Never,
}

impl fmt::Display for ReindexMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReindexMode::Always => write!(f, "always"),
            ReindexMode::OnFailure => write!(f, "on-failure"),
            ReindexMode::Never => write!(f, "never"),
        }
    }
}

pub struct Indexer<'a, DOC> {
    pub stored_topic: &'a str,
    pub indexed_topic: &'a str,
    pub failed_topic: &'a str,
    pub sync_interval: Duration,
    pub indexes: Vec<IndexStore<Box<dyn WriteIndex<Document = DOC>>>>,
    pub storage: Storage,
    pub bus: EventBus,
    pub status: Arc<Mutex<IndexerStatus>>,
    pub commands: Receiver<IndexerCommand>,
    pub command_sender: Sender<IndexerCommand>,
    pub reindex: ReindexMode,
}

impl<'a, DOC> Indexer<'a, DOC>
where
    DOC: 'static,
{
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // Load initial indexes from storage.
        if self.reindex == ReindexMode::Always {
            self.command_sender.send(IndexerCommand::Reindex).await?;
        } else {
            let mut failed = false;
            for index in &self.indexes {
                if let Err(e) = index.sync(&self.storage).await {
                    log::info!("Error loading initial index: {:?}", e);
                    if self.reindex == ReindexMode::OnFailure {
                        failed = true;
                    }
                }
            }

            if (failed && self.reindex == ReindexMode::OnFailure) || self.reindex == ReindexMode::Always {
                self.command_sender.send(IndexerCommand::Reindex).await?;
            }
        }

        let mut interval = tokio::time::interval(self.sync_interval);
        let mut writers = Vec::new();
        for index in &mut self.indexes {
            writers.push(block_in_place(|| index.writer())?);
        }
        let consumer = self.bus.subscribe("indexer", &[self.stored_topic]).await?;
        let mut processed_events = Vec::new();
        let mut indexed_events = Vec::new();
        let mut events = 0;

        *self.status.lock().await = IndexerStatus::Running;
        loop {
            let tick = interval.tick();
            pin_mut!(tick);
            select! {
                command = self.commands.recv() => {
                    if let Some(IndexerCommand::Reindex) = command {
                        self.handle_reindex(&mut writers).await?;
                    }
                }
                event = consumer.next() => match event {
                    Ok(Some(event)) => {
                        if let Some(payload) = event.payload() {
                            if let Ok(data) = self.storage.decode_event(payload) {
                                log::debug!("Received {} records", data.records.len());
                                let mut indexed = 0;
                                for data in data.records {
                                    if self.storage.is_relevant(data.key()) {
                                        match data.event_type() {
                                            EventType::Put => {
                                                match self.storage.get_for_event(&data, true).await {
                                                    Ok(res) => {
                                                        for (index, writer) in self.indexes.iter().zip(writers.iter_mut()) {
                                                            if let Err(e) = self.index_doc(index.index(), writer, &res.key, &res.data).await {
                                                                log::warn!("(Ignored) Internal error when indexing {}: {:?}", res.key, e);
                                                            }
                                                        }
                                                        events += 1;
                                                        indexed += 1;
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Error retrieving document event data, ignoring (error: {:?})", e);
                                                    }
                                                }
                                            },
                                            EventType::Delete => {
                                                let (_, key) = self.storage.key_from_event(&data)?;
                                                for (index, writer) in self.indexes.iter().zip(writers.iter_mut()) {
                                                    block_in_place(|| writer.delete_document(index.index(), key.as_str()));
                                                }
                                                log::info!("Deleted entry '{key}' from index");
                                                events += 1;
                                            }
                                            _ => log::debug!("Non (PUT | DELETE)  event ({:?}), skipping", data),
                                        }
                                    }
                                }
                                if indexed > 0 {
                                    if let Some(payload) = event.payload() {
                                        indexed_events.push(payload.to_vec());
                                    }
                                }
                            } else {
                                log::warn!("Error decoding event, skipping");
                            }
                        } else {
                            log::warn!("No event for payload, skipping");
                        }
                        processed_events.push(event);
                    }
                    Ok(None) => {
                        log::debug!("Polling returned no events, retrying");
                    }
                    Err(BusError::Critical(s)) => {
                        log::warn!("Critical error while polling, exiting: {:?}", s);
                        return Err(anyhow::anyhow!(s));
                    }
                    Err(e) => {
                        log::warn!("Error polling for event: {:?}", e);
                    }
                },
                _ = tick => {
                    log::trace!("{} new events added, pushing new index to storage", events);
                    let mut result = Ok(());
                    for (index, writer) in self.indexes.iter_mut().zip(writers.drain(..)) {
                        if let Err(e) = index.snapshot(writer, &self.storage, events > 0).await {
                            result = Err(e);
                            break;
                        }
                    }

                    match result {
                        Ok(_) => {
                            log::trace!("Index updated successfully");
                            match consumer.commit(&processed_events[..]).await {
                                Ok(_) => {
                                    log::trace!("Event committed successfully");
                                }
                                Err(e) => {
                                    log::warn!("Error committing event: {:?}", e)
                                }
                            }
                            processed_events.clear();
                            events = 0;

                            for payload in indexed_events.drain(..) {
                                // Filter events not related to documents
                                if let Err(e) = self.bus.send(self.indexed_topic, &payload).await {
                                    log::warn!("(Ignored) Error sending event to indexed topic {}: {:?}", self.indexed_topic, e);
                                }
                            }

                        }
                        Err(e) => {
                            log::warn!("Error taking index snapshot: {:?}", e);
                        }
                    }
                    for index in self.indexes.iter_mut() {
                        writers.push(block_in_place(|| index.writer())?);
                    }
                }
            }
        }
    }

    async fn handle_reindex(&mut self, writers: &mut Vec<IndexWriter>) -> anyhow::Result<()> {
        log::info!("Reindexing all documents");

        // set the indexes
        for index in &mut self.indexes {
            index.reset()?;
        }

        // after resetting, we need to acquire new writers, as the old indexes are gone
        writers.clear();
        for index in self.indexes.iter_mut() {
            writers.push(block_in_place(|| index.writer())?);
        }

        // now walk the full content with the new (empty) indexes
        const MAX_RETRIES: usize = 3;
        let mut retries = MAX_RETRIES;
        let mut token = ContinuationToken::default();
        loop {
            retries -= 1;
            match self.reindex(writers, token).await {
                Ok(_) => {
                    log::info!("Reindexing finished");
                    for (index, writer) in self.indexes.iter_mut().zip(writers.drain(..)) {
                        match index.snapshot(writer, &self.storage, true).await {
                            Ok(_) => {
                                log::info!("Reindexed index published");
                            }
                            Err(e) => {
                                log::warn!("(Ignored) Error publishing index: {:?}", e);
                            }
                        }
                    }
                    for index in self.indexes.iter_mut() {
                        writers.push(block_in_place(|| index.writer())?);
                    }
                    *self.status.lock().await = IndexerStatus::Running;
                    break;
                }
                Err((e, resume_token)) => {
                    token = resume_token;
                    log::warn!("Reindexing failed: {:?}. Retries: {}", e, retries);
                    if retries == 0 {
                        panic!("Reindexing failed after {} retries, giving up", MAX_RETRIES);
                    } else {
                        *self.status.lock().await = IndexerStatus::Failed { error: e.to_string() };
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn reindex(
        &mut self,
        writers: &mut Vec<IndexWriter>,
        resume_token: ContinuationToken,
    ) -> Result<(), (IndexerError, ContinuationToken)> {
        let mut progress = 0;
        *self.status.lock().await = IndexerStatus::Reindexing { progress };
        let objects = self.storage.list_objects_from(resume_token.clone());
        pin_mut!(objects);

        let mut interval = tokio::time::interval_at(Instant::now() + self.sync_interval, self.sync_interval);

        loop {
            let tick = interval.tick();
            pin_mut!(tick);
            select! {
                next = objects.next() => {
                    match next {
                        Some(Ok((key, obj))) => {
                            log::info!("Reindexing {:?}", key);
                            // Not sending notifications for reindexing
                            for (index, writer) in self.indexes.iter().zip(writers.iter_mut()) {
                                if let Err(e) = self.index_doc(index.index(), writer, &key, &obj).await {
                                    log::warn!("(Ignored) Internal error when indexing {}: {:?}", key, e);
                                }
                            }
                            progress += 1;
                            *self.status.lock().await = IndexerStatus::Reindexing { progress };
                        }
                        Some(Err((e, resume_token))) => {
                            log::warn!("Error reindexing: {:?}", e);
                            return Err((e.into(), resume_token));
                        }
                        None => {
                            log::info!("All objects traversed");
                            return Ok(());
                        }
                    }
                }
                _ = tick => {
                    for (index, writer) in self.indexes.iter_mut().zip(writers.drain(..)) {
                        match index.snapshot(writer, &self.storage, true).await {
                            Ok(_) => {
                                log::info!("Reindexed snapshot published");
                            }
                            Err(e) => {
                                log::warn!("(Ignored) Error publishing index: {:?}", e);
                            }
                        }
                    }


                    for index in self.indexes.iter_mut() {
                        writers.push(block_in_place(|| index.writer()).map_err(|e| (e.into(), resume_token.clone()))?);
                    }
                }
            }
        }
    }

    async fn index_doc(
        &self,
        index: &dyn WriteIndex<Document = DOC>,
        writer: &mut IndexWriter,
        key: &str,
        data: &[u8],
    ) -> Result<(), anyhow::Error> {
        match block_in_place(|| writer.add_document(index, key, data)) {
            Ok(_) => {
                log::debug!("Inserted entry '{key}' into index");
            }
            Err(e) => {
                let failure = serde_json::json!( {
                    "key": key,
                    "error": e.to_string(),
                })
                .to_string();
                self.bus.send(self.failed_topic, failure.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
enum IndexerError {
    #[error("Storage error: {0}")]
    Storage(trustification_storage::Error),
    #[error("Index error: {0}")]
    Index(trustification_index::Error),
}

impl From<trustification_storage::Error> for IndexerError {
    fn from(e: trustification_storage::Error) -> Self {
        IndexerError::Storage(e)
    }
}

impl From<trustification_index::Error> for IndexerError {
    fn from(e: trustification_index::Error) -> Self {
        IndexerError::Index(e)
    }
}
