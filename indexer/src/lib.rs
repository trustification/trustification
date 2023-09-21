use core::fmt;
use std::time::Duration;

use futures::pin_mut;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::block_in_place;
use tokio::{select, sync::Mutex};
use trustification_event_bus::{Error as BusError, EventBus};
use trustification_index::{Index, IndexStore, IndexWriter};
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

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum ReindexMode {
    #[clap(name = "always")]
    Always,
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

pub struct Indexer<'a, INDEX: Index> {
    pub stored_topic: &'a str,
    pub indexed_topic: &'a str,
    pub failed_topic: &'a str,
    pub sync_interval: Duration,
    pub index: IndexStore<INDEX>,
    pub storage: Storage,
    pub bus: EventBus,
    pub status: Arc<Mutex<IndexerStatus>>,
    pub commands: Receiver<IndexerCommand>,
    pub command_sender: Sender<IndexerCommand>,
    pub reindex: ReindexMode,
}

impl<'a, INDEX: Index> Indexer<'a, INDEX> {
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // Load initial index from storage.
        if let Err(e) = self.index.sync(&self.storage).await {
            log::info!("Error loading initial index: {:?}", e);
            if self.reindex == ReindexMode::OnFailure || self.reindex == ReindexMode::Always {
                self.command_sender.send(IndexerCommand::Reindex).await?;
            }
        } else if self.reindex == ReindexMode::Always {
            self.command_sender.send(IndexerCommand::Reindex).await?;
        }

        let mut interval = tokio::time::interval(self.sync_interval);
        let mut writer = Some(block_in_place(|| self.index.writer())?);
        let consumer = self.bus.subscribe("indexer", &[self.stored_topic]).await?;
        let mut uncommitted_events = Vec::new();
        let mut events = 0;
        let mut indexed = Vec::new();

        *self.status.lock().await = IndexerStatus::Running;
        loop {
            let tick = interval.tick();
            pin_mut!(tick);
            select! {
                command = self.commands.recv() => {
                    if let Some(IndexerCommand::Reindex) = command {
                        self.index.reset()?;
                        log::info!("Reindexing all documents");
                        const MAX_RETRIES: usize = 3;
                        let mut retries = MAX_RETRIES;
                        let mut token = ContinuationToken::default();
                        loop {
                            retries -= 1;
                            match self.reindex(&mut writer, token).await {
                                Ok(_) => {
                                    log::info!("Reindexing finished");
                                    match self.index.snapshot(writer.take().unwrap(), &self.storage, true).await {
                                        Ok(_) => {
                                            log::info!("Reindexed index published");
                                        }
                                        Err(e) => {
                                            log::warn!("(Ignored) Error publishing index: {:?}", e);
                                        }
                                    }
                                    writer.replace(block_in_place(|| self.index.writer())?);
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
                    }
                }
                event = consumer.next() => match event {
                    Ok(Some(event)) => {
                        if let Some(payload) = event.payload() {
                            if let Ok(data) = self.storage.decode_event(payload) {
                                for data in data.records {
                                    if self.storage.is_index(data.key()) {
                                        log::trace!("It's an index event, ignoring");
                                    } else {
                                        match data.event_type() {
                                            EventType::Put => {
                                                match self.storage.get_for_event(&data, true).await {
                                                    Ok(res) => {
                                                        if let Err(e) = self.index_doc(self.index.index(), writer.as_mut().unwrap(), &res.key, &res.data, &mut indexed).await {
                                                            log::warn!("(Ignored) Internal error when indexing {}: {:?}", res.key, e);
                                                        }
                                                        events += 1;
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Error retrieving document event data, ignoring (error: {:?})", e);
                                                    }
                                                }
                                            },
                                            EventType::Delete => {
                                                let (_, key) = Storage::key_from_event(&data)?;
                                                block_in_place(|| writer.as_mut().unwrap().delete_document(self.index.index(), key.as_str()));
                                                log::debug!("Deleted entry '{key}' from index");
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
                    match self.index.snapshot(writer.take().unwrap(), &self.storage, events > 0).await {
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

                            for key in indexed.drain(..) {
                                if let Err(e) = self.bus.send(self.indexed_topic, key.as_bytes()).await {
                                    log::warn!("(Ignored) Error sending key {} to indexed topic {}: {:?}", key, self.indexed_topic, e);
                                }
                            }

                        }
                        Err(e) => {
                            log::warn!("Error taking index snapshot: {:?}", e);
                        }
                    }
                    writer.replace(block_in_place(|| self.index.writer())?);
                }
            }
        }
    }

    async fn reindex(
        &mut self,
        writer: &mut Option<IndexWriter>,
        resume_token: ContinuationToken,
    ) -> Result<(), (IndexerError, ContinuationToken)> {
        let mut progress = 0;
        *self.status.lock().await = IndexerStatus::Reindexing { progress };
        let objects = self.storage.list_objects_from(resume_token.clone());
        pin_mut!(objects);

        let mut interval = tokio::time::interval(self.sync_interval);

        loop {
            let tick = interval.tick();
            pin_mut!(tick);
            select! {
                next = objects.next() => {
                    match next {
                        Some(Ok((path, obj))) => {
                            let key = path.key();
                            log::info!("Reindexing {:?}", key);
                            // Not sending notifications for reindexing
                            if let Err(e) = self.index_doc(self.index.index(), writer.as_mut().unwrap(), key, &obj, &mut Vec::new()).await {
                                log::warn!("(Ignored) Internal error when indexing {}: {:?}", key, e);
                            } else {
                                progress += 1;
                                *self.status.lock().await = IndexerStatus::Reindexing { progress };
                            }
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
                    match self.index.commit(writer.take().unwrap()) {
                        Ok(_) => {
                            log::trace!("Index committed");
                        }
                        Err(e) => {
                            log::warn!("(Ignored) Error committing index: {:?}", e);
                        }
                    }
                    writer.replace(block_in_place(|| self.index.writer()).map_err(|e| (e.into(), resume_token.clone()))?);
                }
            }
        }
    }

    async fn index_doc(
        &self,
        index: &INDEX,
        writer: &mut IndexWriter,
        key: &str,
        data: &[u8],
        indexed: &mut Vec<String>,
    ) -> Result<(), anyhow::Error> {
        match block_in_place(|| writer.add_document(index, key, data)) {
            Ok(_) => {
                log::debug!("Inserted entry '{key}' into index");
                indexed.push(key.to_string());
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
