pub mod metadata;
mod s3dir;

use prometheus::{
    histogram_opts, opts, register_histogram_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry, Histogram, IntCounter, IntGauge, Registry,
};
use s3dir::S3Directory;
use sikula::prelude::{Ordered, Primary, Search};
use std::{
    fmt::{Debug, Display},
    ops::Bound,
    path::{Path, PathBuf},
};
use trustification_api::search::SearchOptions;
use trustification_storage::{Storage, StorageConfig};
// Rexport to align versions
use log::{debug, warn};
use sha2::{Digest, Sha256};
use std::sync::RwLock;
pub use tantivy;
pub use tantivy::schema::Document;
use tantivy::{
    directory::{MmapDirectory, INDEX_WRITER_LOCK},
    query::{AllQuery, BooleanQuery, BoostQuery, Occur, Query, RangeQuery, RegexQuery, TermQuery},
    schema::*,
    DateTime, Directory, DocAddress, Index as SearchIndex, IndexSettings, Searcher,
};
use time::{OffsetDateTime, UtcOffset};

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct IndexConfig {
    /// Local folder to store index.
    #[arg(env = "INDEX_DIR", short = 'i', long = "index-dir")]
    pub index_dir: Option<std::path::PathBuf>,

    /// Synchronization interval for index persistence.
    #[arg(env = "INDEX_SYNC_INTERVAL", long = "index-sync-interval", default_value = "30s")]
    pub sync_interval: humantime::Duration,

    /// Memory available to index writer
    #[arg(env = "INDEX_WRITER_MEMORY_BYTES", long = "index-writer-memory-bytes", default_value_t = 32 * 1024 * 1024)]
    pub index_writer_memory_bytes: usize,

    /// Synchronization interval for index persistence.
    #[arg(env = "INDEX_MODE", long = "index-mode", default_value_t = IndexMode::File)]
    pub mode: IndexMode,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum IndexMode {
    File,
    S3,
}

impl Display for IndexMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::S3 => write!(f, "s3"),
        }
    }
}

impl Default for IndexMode {
    fn default() -> Self {
        Self::File
    }
}

#[derive(Clone)]
struct Metrics {
    indexed_total: IntCounter,
    failed_total: IntCounter,
    snapshots_total: IntCounter,
    queries_total: IntCounter,
    index_size_disk_bytes: IntGauge,
    indexing_latency_seconds: Histogram,
    query_latency_seconds: Histogram,
}

impl Metrics {
    fn register(registry: &Registry) -> Result<Self, Error> {
        let indexed_total = register_int_counter_with_registry!(
            opts!("index_indexed_total", "Total number of indexing operations"),
            registry
        )?;

        let failed_total = register_int_counter_with_registry!(
            opts!("index_failed_total", "Total number of indexing operations failed"),
            registry
        )?;

        let queries_total = register_int_counter_with_registry!(
            opts!("index_queries_total", "Total number of search queries"),
            registry
        )?;

        let snapshots_total = register_int_counter_with_registry!(
            opts!("index_snapshots_total", "Total number of snapshots taken"),
            registry
        )?;

        let index_size_disk_bytes = register_int_gauge_with_registry!(
            opts!("index_size_disk_bytes", "Amount of bytes consumed by index on disk"),
            registry
        )?;

        let indexing_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                "index_indexing_latency_seconds",
                "Indexing latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        let query_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                "index_query_latency_seconds",
                "Search query latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        Ok(Self {
            indexed_total,
            failed_total,
            snapshots_total,
            queries_total,
            index_size_disk_bytes,
            indexing_latency_seconds,
            query_latency_seconds,
        })
    }
}

pub struct IndexStore<INDEX: Index> {
    inner: RwLock<SearchIndex>,
    index_dir: Option<RwLock<IndexDirectory>>,
    index: INDEX,
    index_writer_memory_bytes: usize,
    metrics: Metrics,
}

pub trait Index {
    type MatchedDocument: core::fmt::Debug;
    type Document;
    type QueryContext: core::fmt::Debug;

    fn parse_doc(data: &[u8]) -> Result<Self::Document, Error>;
    fn settings(&self) -> IndexSettings;
    fn schema(&self) -> Schema;
    fn prepare_query(&self, q: &str) -> Result<Self::QueryContext, Error>;
    fn search(
        &self,
        searcher: &Searcher,
        query: &Self::QueryContext,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<(f32, DocAddress)>, usize), Error>;
    fn process_hit(
        &self,
        doc: DocAddress,
        score: f32,
        searcher: &Searcher,
        query: &Self::QueryContext,
        options: &SearchOptions,
    ) -> Result<Self::MatchedDocument, Error>;
    fn index_doc(&self, id: &str, document: &Self::Document) -> Result<Document, Error>;
    fn doc_id_to_term(&self, id: &str) -> Term;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("error opening index {0}")]
    Open(String),
    #[error("error taking snapshot of index")]
    Snapshot,
    #[error("index not found")]
    NotFound,
    #[error("operation cannot be done because index is not persisted")]
    NotPersisted,
    #[error("error parsing document {0}")]
    DocParser(String),
    #[error("error parsing query {0}")]
    QueryParser(String),
    #[error("error from storage {0}")]
    Storage(trustification_storage::Error),
    #[error("invalid limit parameter {0}")]
    InvalidLimitParameter(usize),
    #[error("error from search {0}")]
    Search(tantivy::TantivyError),
    #[error("error configuring metrics {0}")]
    Prometheus(prometheus::Error),
    #[error("I/O error {0}")]
    Io(std::io::Error),
}

impl From<prometheus::Error> for Error {
    fn from(e: prometheus::Error) -> Self {
        Self::Prometheus(e)
    }
}

impl From<tantivy::TantivyError> for Error {
    fn from(e: tantivy::TantivyError) -> Self {
        Self::Search(e)
    }
}

impl From<trustification_storage::Error> for Error {
    fn from(e: trustification_storage::Error) -> Self {
        Self::Storage(e)
    }
}

pub struct IndexWriter {
    writer: tantivy::IndexWriter,
    metrics: Metrics,
}

impl IndexWriter {
    pub fn add_document<INDEX: Index>(&mut self, index: &INDEX, id: &str, data: &[u8]) -> Result<(), Error> {
        let indexing_latency = self.metrics.indexing_latency_seconds.start_timer();
        match INDEX::parse_doc(data) {
            Ok(doc) => {
                let doc = index.index_doc(id, &doc).map_err(|e| {
                    self.metrics.failed_total.inc();
                    e
                })?;
                self.delete_document(index, id);
                self.writer.add_document(doc).map_err(|e| {
                    self.metrics.failed_total.inc();
                    e
                })?;
                self.metrics.indexed_total.inc();
            }
            Err(e) => {
                log::warn!("Error parsing document with id '{id}': {e:?}");
                self.metrics.failed_total.inc();
            }
        }
        self.metrics.indexed_total.inc();
        indexing_latency.observe_duration();
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.writer.commit()?;
        self.writer.wait_merging_threads()?;
        Ok(())
    }

    pub fn delete_document<INDEX: Index>(&self, index: &INDEX, key: &str) {
        let term = index.doc_id_to_term(key);
        self.writer.delete_term(term);
    }
}

#[derive(Debug)]
struct IndexDirectory {
    path: PathBuf,
    state: IndexState,
    digest: Vec<u8>,
}

impl IndexDirectory {
    /// Attempt to build a new index from the serialized zstd data
    pub fn sync(&mut self, schema: Schema, settings: IndexSettings, data: &[u8]) -> Result<Option<SearchIndex>, Error> {
        let digest = Sha256::digest(data).to_vec();
        if self.digest != digest {
            let next = self.state.next();
            let path = next.directory(&self.path);
            let index = self.unpack(schema, settings, data, &path)?;
            self.state = next;
            self.digest = digest;
            Ok(Some(index))
        } else {
            Ok(None)
        }
    }

    pub fn new(path: &PathBuf) -> Result<IndexDirectory, Error> {
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        }
        std::fs::create_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        let state = IndexState::A;
        Ok(Self {
            digest: Vec::new(),
            path: path.clone(),
            state,
        })
    }

    pub fn build(&self, settings: IndexSettings, schema: Schema) -> Result<SearchIndex, Error> {
        let path = self.state.directory(&self.path);
        std::fs::create_dir_all(&path).map_err(|e| Error::Open(e.to_string()))?;
        let dir = MmapDirectory::open(&path).map_err(|e| Error::Open(e.to_string()))?;
        let builder = SearchIndex::builder().schema(schema).settings(settings);
        let index = builder.open_or_create(dir).map_err(|e| Error::Open(e.to_string()))?;
        Ok(index)
    }

    fn unpack(
        &mut self,
        schema: Schema,
        settings: IndexSettings,
        data: &[u8],
        path: &Path,
    ) -> Result<SearchIndex, Error> {
        if path.exists() {
            std::fs::remove_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;
        }
        std::fs::create_dir_all(path).map_err(|e| Error::Open(e.to_string()))?;

        let dec = zstd::stream::Decoder::new(data).map_err(Error::Io)?;
        let mut archive = tar::Archive::new(dec);
        archive.unpack(path).map_err(Error::Io)?;
        log::trace!("Unpacked into {:?}", path);

        let dir = MmapDirectory::open(path).map_err(|e| Error::Open(e.to_string()))?;
        let builder = SearchIndex::builder().schema(schema).settings(settings);
        let inner = builder.open_or_create(dir).map_err(|e| Error::Open(e.to_string()))?;
        Ok(inner)
    }

    pub fn pack(&mut self) -> Result<Vec<u8>, Error> {
        let path = self.state.directory(&self.path);
        let mut out = Vec::new();
        let enc = zstd::stream::Encoder::new(&mut out, 3).map_err(Error::Io)?;
        let mut archive = tar::Builder::new(enc.auto_finish());
        log::trace!("Packing from {:?}", path);
        archive.append_dir_all("", path).map_err(Error::Io)?;
        drop(archive);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum IndexState {
    A,
    B,
}

impl IndexState {
    fn directory(&self, root: &Path) -> PathBuf {
        match self {
            Self::A => root.join("a"),
            Self::B => root.join("b"),
        }
    }

    fn next(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

impl<INDEX: Index> IndexStore<INDEX> {
    pub fn new_in_memory(index: INDEX) -> Result<Self, Error> {
        let schema = index.schema();
        let settings = index.settings();
        let builder = SearchIndex::builder().schema(schema).settings(settings);
        let inner = builder.create_in_ram()?;
        Ok(Self {
            inner: RwLock::new(inner),
            index,
            index_writer_memory_bytes: 32 * 1024 * 1024,
            index_dir: None,
            metrics: Metrics::register(&Default::default())?,
        })
    }

    pub fn new(
        storage: &StorageConfig,
        config: &IndexConfig,
        index: INDEX,
        metrics_registry: &Registry,
    ) -> Result<Self, Error> {
        match config.mode {
            IndexMode::File => {
                let path = config.index_dir.clone().unwrap_or_else(|| {
                    use rand::RngCore;
                    let r = rand::thread_rng().next_u32();
                    std::env::temp_dir().join(format!("index.{}", r))
                });

                let schema = index.schema();
                let settings = index.settings();

                let index_dir = IndexDirectory::new(&path)?;
                let inner = index_dir.build(settings, schema)?;
                Ok(Self {
                    inner: RwLock::new(inner),
                    index_writer_memory_bytes: config.index_writer_memory_bytes,
                    index_dir: Some(RwLock::new(index_dir)),
                    index,
                    metrics: Metrics::register(metrics_registry)?,
                })
            }
            IndexMode::S3 => {
                let bucket = storage.clone().try_into()?;
                let schema = index.schema();
                let settings = index.settings();
                let builder = SearchIndex::builder().schema(schema).settings(settings);
                let dir = S3Directory::new(bucket);
                let inner = builder.open_or_create(dir)?;
                Ok(Self {
                    inner: RwLock::new(inner),
                    index_writer_memory_bytes: config.index_writer_memory_bytes,
                    index_dir: None,
                    index,
                    metrics: Metrics::register(metrics_registry)?,
                })
            }
        }
    }

    pub fn index(&self) -> &INDEX {
        &self.index
    }

    pub fn index_as_mut(&mut self) -> &mut INDEX {
        &mut self.index
    }

    /// Sync the index from a snapshot.
    ///
    /// NOTE: Only applicable for file indices.
    ///
    /// # Safety
    ///
    /// Only a single thread should call this method at a time. If not, it will panic while acquiring the RefCell
    pub async fn sync(&self, storage: &Storage) -> Result<(), Error> {
        if let Some(index_dir) = &self.index_dir {
            let data = storage.get_index().await?;
            let mut index_dir = index_dir.write().unwrap();
            match index_dir.sync(self.index.schema(), self.index.settings(), &data) {
                Ok(Some(index)) => {
                    *self.inner.write().unwrap() = index;
                    log::debug!("Index reloaded");
                }
                Ok(None) => {
                    // No index change
                }
                Err(e) => {
                    log::warn!("Error syncing index: {:?}, keeping old", e);
                }
            }
            log::debug!("Index reloaded");
        }
        Ok(())
    }

    /// Take a snapshot of the index and push to object storage.
    ///
    /// NOTE: Only applicable for file indices.
    ///
    ///
    // Disable the lint due to a [bug in clippy](https://github.com/rust-lang/rust-clippy/issues/6446).
    #[allow(clippy::await_holding_lock)]
    pub async fn snapshot(&mut self, writer: IndexWriter, storage: &Storage, force: bool) -> Result<(), Error> {
        if let Some(index_dir) = &self.index_dir {
            writer.commit()?;

            let mut dir = index_dir.write().unwrap();
            let mut inner = self.inner.write().unwrap();
            inner.directory_mut().sync_directory().map_err(Error::Io)?;
            let lock = inner.directory_mut().acquire_lock(&INDEX_WRITER_LOCK);

            let managed_files = inner.directory().list_managed_files();

            let mut total_size: i64 = 0;
            for file in managed_files.iter() {
                log::trace!("Managed file: {:?}", file);
                let sz = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
                total_size += sz as i64;
            }
            self.metrics.index_size_disk_bytes.set(total_size);
            self.metrics.snapshots_total.inc();

            let gc_result = inner.directory_mut().garbage_collect(|| managed_files)?;
            log::trace!(
                "Gc result. Deleted: {:?}, failed: {:?}",
                gc_result.deleted_files,
                gc_result.failed_to_delete_files
            );
            let changed = !gc_result.deleted_files.is_empty();
            inner.directory_mut().sync_directory().map_err(Error::Io)?;
            if force || changed {
                log::info!("Index has changed, publishing new snapshot");
                let out = dir.pack()?;
                drop(lock);
                drop(inner);
                drop(dir);
                match storage.put_index(&out).await {
                    Ok(_) => {
                        log::trace!("Snapshot published successfully");
                        Ok(())
                    }
                    Err(e) => {
                        log::warn!("Error updating index: {:?}", e);
                        Err(e.into())
                    }
                }
            } else {
                log::trace!("No changes to index");
                Ok(())
            }
        } else {
            log::trace!("Committing index");
            writer.commit()?;
            Ok(())
        }
    }

    pub fn writer(&mut self) -> Result<IndexWriter, Error> {
        let writer = self.inner.write().unwrap().writer(self.index_writer_memory_bytes)?;
        Ok(IndexWriter {
            writer,
            metrics: self.metrics.clone(),
        })
    }

    pub fn search(
        &self,
        q: &str,
        offset: usize,
        limit: usize,
        options: SearchOptions,
    ) -> Result<(Vec<INDEX::MatchedDocument>, usize), Error> {
        let latency = self.metrics.query_latency_seconds.start_timer();

        if limit == 0 {
            return Err(Error::InvalidLimitParameter(limit));
        }

        let inner = self.inner.read().unwrap();
        let reader = inner.reader()?;
        let searcher = reader.searcher();

        let query = self.index.prepare_query(q)?;

        debug!("Processed query: {:?}", query);

        let (top_docs, count) = self.index.search(&searcher, &query, offset, limit)?;

        self.metrics.queries_total.inc();

        log::info!("#matches={count} for query '{q}'");

        if options.summaries {
            let mut hits = Vec::new();
            for hit in top_docs {
                if let Ok(value) = self.index.process_hit(hit.1, hit.0, &searcher, &query, &options) {
                    debug!("HIT: {:?}", value);
                    hits.push(value);
                } else {
                    warn!("Error processing hit {:?}", hit);
                }
            }

            debug!("Filtered to {}", hits.len());

            latency.observe_duration();
            Ok((hits, count))
        } else {
            latency.observe_duration();
            Ok((Vec::new(), count))
        }
    }
}

/// Convert a sikula term to a query
pub fn term2query<'m, R: Search, F: Fn(&R::Parsed<'m>) -> Box<dyn Query>>(
    term: &sikula::prelude::Term<'m, R>,
    f: &F,
) -> Box<dyn Query> {
    match term {
        sikula::prelude::Term::Match(resource) => f(resource),
        sikula::prelude::Term::Not(term) => {
            let all: Box<dyn Query> = Box::new(AllQuery);
            let query_terms = vec![(Occur::Should, all), (Occur::MustNot, term2query(term, f))];
            let query = BooleanQuery::new(query_terms);
            Box::new(query)
        }
        sikula::prelude::Term::And(terms) => {
            let mut query_terms = Vec::new();
            for term in terms {
                query_terms.push(term2query(term, f));
            }
            Box::new(BooleanQuery::intersection(query_terms))
        }
        sikula::prelude::Term::Or(terms) => {
            let mut query_terms = Vec::new();
            for term in terms {
                query_terms.push(term2query(term, f));
            }
            Box::new(BooleanQuery::union(query_terms))
        }
    }
}

/// Crate a date query based on an ordered value
pub fn create_date_query(field: Field, field_str: &str, value: &Ordered<time::OffsetDateTime>) -> Box<dyn Query> {
    match value {
        Ordered::Less(e) => Box::new(RangeQuery::new_term_bounds(
            field_str.to_string(),
            Type::Date,
            &Bound::Unbounded,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::LessEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_str.to_string(),
            Type::Date,
            &Bound::Unbounded,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::Greater(e) => Box::new(RangeQuery::new_term_bounds(
            field_str.to_string(),
            Type::Date,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::GreaterEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field_str.to_string(),
            Type::Date,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::Equal(e) => {
            let theday = e.to_offset(UtcOffset::UTC).date();
            let theday_after = theday.next_day().unwrap_or(theday);

            let theday = theday.midnight().assume_utc();
            let theday_after = theday_after.midnight().assume_utc();

            let from = Bound::Included(Term::from_field_date(field, DateTime::from_utc(theday)));
            let to = Bound::Included(Term::from_field_date(field, DateTime::from_utc(theday_after)));
            Box::new(RangeQuery::new_term_bounds(
                field_str.to_string(),
                Type::Date,
                &from,
                &to,
            ))
        }
        Ordered::Range(from, to) => {
            let from = bound_map(*from, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            let to = bound_map(*to, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            Box::new(RangeQuery::new_term_bounds(
                field_str.to_string(),
                Type::Date,
                &from,
                &to,
            ))
        }
    }
}

/// Convert a sikula primary to a tantivy query for string fields
pub fn create_string_query(field: Field, primary: &Primary<'_>) -> Box<dyn Query> {
    match primary {
        Primary::Equal(value) => Box::new(TermQuery::new(Term::from_field_text(field, value), Default::default())),
        Primary::Partial(value) => {
            // Note: This could be expensive so consider alternatives
            let pattern = format!(".*{}.*", value);
            let mut queries: Vec<Box<dyn Query>> = Vec::new();
            if let Ok(query) = RegexQuery::from_pattern(&pattern, field) {
                queries.push(Box::new(query));
            } else {
                warn!("Unable to partial query from {}", pattern);
            }
            queries.push(Box::new(TermQuery::new(
                Term::from_field_text(field, value),
                Default::default(),
            )));
            Box::new(BooleanQuery::union(queries))
        }
    }
}

/// Convert a sikula primary to a tantivy query for text fields
pub fn create_text_query(field: Field, primary: &Primary<'_>) -> Box<dyn Query> {
    match primary {
        Primary::Equal(value) => Box::new(TermQuery::new(Term::from_field_text(field, value), Default::default())),
        Primary::Partial(value) => Box::new(TermQuery::new(Term::from_field_text(field, value), Default::default())),
    }
}

/// Boost score of a term
pub fn boost(q: Box<dyn Query>, weight: f32) -> Box<dyn Query> {
    Box::new(BoostQuery::new(q, weight))
}

/// Map over a bound
pub fn bound_map<F: FnOnce(T) -> R, T, R>(bound: Bound<T>, func: F) -> Bound<R> {
    match bound {
        Bound::Included(f) => Bound::Included(func(f)),
        Bound::Excluded(f) => Bound::Excluded(func(f)),
        Bound::Unbounded => Bound::Unbounded,
    }
}

/// Create a boolean query
pub fn create_boolean_query(occur: Occur, term: Term) -> Box<dyn Query> {
    Box::new(BooleanQuery::new(vec![(
        occur,
        Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
    )]))
}

pub fn field2strvec(doc: &Document, field: Field) -> Result<Vec<&str>, Error> {
    Ok(doc.get_all(field).map(|s| s.as_text().unwrap_or_default()).collect())
}

pub fn field2f64vec(doc: &Document, field: Field) -> Result<Vec<f64>, Error> {
    Ok(doc.get_all(field).map(|s| s.as_f64().unwrap_or_default()).collect())
}

pub fn field2str(doc: &Document, field: Field) -> Result<&str, Error> {
    let value = doc.get_first(field).map(|s| s.as_text()).unwrap_or(None);
    value.map(Ok).unwrap_or(Err(Error::NotFound))
}

pub fn field2date(doc: &Document, field: Field) -> Result<OffsetDateTime, Error> {
    let value = doc.get_first(field).map(|s| s.as_date()).unwrap_or(None);
    value.map(|v| Ok(v.into_utc())).unwrap_or(Err(Error::NotFound))
}

pub fn field2float(doc: &Document, field: Field) -> Result<f64, Error> {
    let value = doc.get_first(field).map(|s| s.as_f64()).unwrap_or(None);
    value.map(Ok).unwrap_or(Err(Error::NotFound))
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use tantivy::collector::TopDocs;
    use tantivy::doc;

    use super::*;

    struct TestIndex {
        schema: Schema,
        id: Field,
        text: Field,
    }

    impl TestIndex {
        pub fn new() -> Self {
            let mut builder = Schema::builder();
            let id = builder.add_text_field("id", STRING | FAST | STORED);
            let text = builder.add_text_field("text", TEXT);
            let schema = builder.build();
            Self { schema, id, text }
        }
    }

    impl Index for TestIndex {
        type MatchedDocument = String;
        type Document = String;
        type QueryContext = Box<dyn Query>;

        fn settings(&self) -> IndexSettings {
            IndexSettings::default()
        }

        fn schema(&self) -> Schema {
            self.schema.clone()
        }

        fn parse_doc(data: &[u8]) -> Result<Self::Document, Error> {
            core::str::from_utf8(data)
                .map_err(|e| Error::DocParser(e.to_string()))
                .map(|s| s.to_string())
        }

        fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, Error> {
            let queries: Vec<Box<dyn Query>> = vec![
                Box::new(TermQuery::new(
                    Term::from_field_text(self.id, q),
                    IndexRecordOption::Basic,
                )),
                Box::new(TermQuery::new(
                    Term::from_field_text(self.text, q),
                    IndexRecordOption::Basic,
                )),
            ];
            Ok(Box::new(BooleanQuery::union(queries)))
        }

        fn process_hit(
            &self,
            doc: DocAddress,
            _score: f32,
            searcher: &Searcher,
            _query: &Box<dyn Query>,
            _options: &SearchOptions,
        ) -> Result<Self::MatchedDocument, Error> {
            let d = searcher.doc(doc)?;
            let id = d.get_first(self.id).map(|v| v.as_text()).ok_or(Error::NotFound)?;
            Ok(id.unwrap_or("").to_string())
        }

        fn search(
            &self,
            searcher: &Searcher,
            query: &Box<dyn Query>,
            offset: usize,
            limit: usize,
        ) -> Result<(Vec<(f32, DocAddress)>, usize), Error> {
            Ok(searcher.search(
                query,
                &(TopDocs::with_limit(limit).and_offset(offset), tantivy::collector::Count),
            )?)
        }

        fn index_doc(&self, id: &str, document: &Self::Document) -> Result<Document, Error> {
            let doc = tantivy::doc!(
                self.id => id.to_string(),
                self.text => document.to_string()
            );
            Ok(doc)
        }

        fn doc_id_to_term(&self, id: &str) -> Term {
            Term::from_field_text(self.id, id)
        }
    }

    #[tokio::test]
    async fn test_basic_index() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default(),).unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_index_removal() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default(),).unwrap().1, 1);

        let writer = store.writer().unwrap();
        writer.delete_document(store.index_as_mut(), "foo");
        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default(),).unwrap().1, 0);
    }

    #[tokio::test]
    async fn test_zero_limit() {
        let _ = env_logger::try_init();
        let store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        assert!(matches!(
            store.search("is", 0, 0, SearchOptions::default()),
            Err(Error::InvalidLimitParameter(0))
        ));
    }

    #[tokio::test]
    async fn test_duplicates() {
        let _ = env_logger::try_init();
        let mut store = IndexStore::new_in_memory(TestIndex::new()).unwrap();
        let mut writer = store.writer().unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default(),).unwrap().1, 1);

        // Duplicates also removed if separate commits.
        let mut writer = store.writer().unwrap();
        writer
            .add_document(store.index_as_mut(), "foo", b"Foo is great")
            .unwrap();

        writer.commit().unwrap();

        assert_eq!(store.search("is", 0, 10, SearchOptions::default(),).unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_directory_sync_failure() {
        let _ = env_logger::try_init();

        let mut old_schema = Schema::builder();
        let old_id = old_schema.add_text_field("id", STRING | FAST | STORED);
        let old_schema = old_schema.build();

        let mut new_schema = Schema::builder();
        new_schema.add_u64_field("id", INDEXED);
        let new_schema = new_schema.build();

        let r = rand::thread_rng().next_u32();
        let dir = std::env::temp_dir().join(format!("index.{}", r));

        let mut good = IndexDirectory::new(&dir.join("good")).unwrap();
        let mut bad = IndexDirectory::new(&dir.join("bad")).unwrap();

        let store = good.build(Default::default(), old_schema).unwrap();

        let mut w = store.writer(10_000_000).unwrap();
        w.add_document(doc!(old_id => "foo")).unwrap();
        w.commit().unwrap();
        w.wait_merging_threads().unwrap();

        let snapshot = good.pack().unwrap();
        let store = bad.build(Default::default(), new_schema).unwrap();
        let schema = store.schema();
        let settings = store.settings();

        assert_eq!(bad.state, IndexState::A);
        let result = bad.sync(schema, settings.clone(), &snapshot);
        assert!(result.is_err());
        assert_eq!(bad.state, IndexState::A);
    }
}
