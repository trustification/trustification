use std::{fmt::Display, ops::Bound, path::PathBuf};

use sikula::prelude::{Ordered, Primary, Search};
// Rexport to align versions
pub use tantivy;
pub use tantivy::schema::Document;
use tantivy::{
    collector::{Count, TopDocs},
    directory::{MmapDirectory, INDEX_WRITER_LOCK},
    query::{BooleanQuery, Occur, Query, RangeQuery, TermQuery},
    schema::*,
    DateTime, Directory, Index as SearchIndex, IndexWriter,
};
use tracing::{info, warn};

pub struct IndexStore<INDEX: Index> {
    inner: SearchIndex,
    path: Option<PathBuf>,
    index: INDEX,
}

pub trait Index {
    type MatchedDocument;
    type Document;

    fn schema(&self) -> Schema;
    fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, Error>;
    fn process_hit(&self, doc: Document) -> Result<Self::MatchedDocument, Error>;
    fn index_doc(&self, document: &Self::Document) -> Result<Vec<Document>, Error>;
}

#[derive(Debug)]
pub enum Error {
    Open,
    Snapshot,
    NotFound,
    NotPersisted,
    Parser(String),
    Search(tantivy::TantivyError),
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Error opening index"),
            Self::Snapshot => write!(f, "Error snapshotting index"),
            Self::NotFound => write!(f, "Not found"),
            Self::NotPersisted => write!(f, "Database is not persisted"),
            Self::Parser(e) => write!(f, "Failed to parse query: {e}"),
            Self::Search(e) => write!(f, "Error in search index: {:?}", e),
            Self::Io(e) => write!(f, "I/O error: {:?}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<tantivy::TantivyError> for Error {
    fn from(e: tantivy::TantivyError) -> Self {
        Self::Search(e)
    }
}

pub struct Indexer {
    writer: IndexWriter,
}

impl Indexer {
    pub fn index<INDEX: Index>(&mut self, index: &mut INDEX, raw: &INDEX::Document) -> Result<(), Error> {
        let docs = index.index_doc(raw)?;
        for doc in docs {
            self.writer.add_document(doc)?;
        }
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.writer.commit()?;
        self.writer.wait_merging_threads()?;
        Ok(())
    }
}

impl<INDEX: Index> IndexStore<INDEX> {
    pub fn new_in_memory(index: INDEX) -> Result<Self, Error> {
        let schema = index.schema();
        let inner = SearchIndex::create_in_ram(schema);
        Ok(Self {
            inner,
            index,
            path: None,
        })
    }

    pub fn new(path: &PathBuf, index: INDEX) -> Result<Self, Error> {
        let schema = index.schema();
        let dir = MmapDirectory::open(path).map_err(|_e| Error::Open)?;
        let inner = SearchIndex::open_or_create(dir, schema)?;
        Ok(Self {
            inner,
            path: Some(path.clone()),
            index,
        })
    }

    pub fn index(&mut self) -> &mut INDEX {
        &mut self.index
    }

    pub fn restore(path: &PathBuf, data: &[u8], index: INDEX) -> Result<Self, Error> {
        let dec = zstd::stream::Decoder::new(data).map_err(Error::Io)?;
        let mut archive = tar::Archive::new(dec);
        archive.unpack(path).map_err(Error::Io)?;
        Self::new(path, index)
    }

    pub fn reload(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(path) = &self.path {
            let dec = zstd::stream::Decoder::new(data).map_err(Error::Io)?;
            let mut archive = tar::Archive::new(dec);
            archive.unpack(path).map_err(Error::Io)?;
        }
        Ok(())
    }

    pub fn snapshot(&mut self, indexer: Indexer) -> Result<Vec<u8>, Error> {
        if let Some(path) = &self.path {
            tracing::info!("Committing index to path {:?}", path);
            indexer.commit()?;
            self.inner.directory_mut().sync_directory().map_err(Error::Io)?;
            let lock = self.inner.directory_mut().acquire_lock(&INDEX_WRITER_LOCK);

            let mut out = Vec::new();
            tracing::info!("Creating encoder");
            let enc = zstd::stream::Encoder::new(&mut out, 3).map_err(Error::Io)?;
            tracing::info!("Creating builder");
            let mut archive = tar::Builder::new(enc.auto_finish());
            tracing::info!("Adding directories from {:?}", path);
            archive.append_dir_all("", path).map_err(Error::Io)?;
            tracing::info!("Added it all to the archive");
            drop(archive);
            drop(lock);
            Ok(out)
        } else {
            Err(Error::NotPersisted)
        }
    }

    pub fn indexer(&mut self) -> Result<Indexer, Error> {
        let writer = self.inner.writer(100_000_000)?;
        Ok(Indexer { writer })
    }

    pub fn search(&self, q: &str, offset: usize, len: usize) -> Result<(Vec<INDEX::MatchedDocument>, usize), Error> {
        let reader = self.inner.reader()?;
        let searcher = reader.searcher();

        let query = self.index.prepare_query(q)?;

        info!("Processed query: {:?}", query);

        let (top_docs, count) = searcher.search(&query, &(TopDocs::with_limit(len).and_offset(offset), Count))?;

        tracing::debug!("Found {} docs", count);

        let mut hits = Vec::new();
        for hit in top_docs {
            let doc = searcher.doc(hit.1)?;
            if let Ok(value) = self.index.process_hit(doc) {
                hits.push(value);
            } else {
                warn!("Error processing hit {:?}", hit);
            }
        }

        tracing::trace!("Filtered to {}", hits.len());

        Ok((hits, count))
    }
}

/// Convert a sikula term to a query
pub fn term2query<'m, R: Search<'m>, F: Fn(&R::Parsed) -> Box<dyn Query>>(
    term: &sikula::prelude::Term<'m, R>,
    f: &F,
) -> Box<dyn Query> {
    match term {
        sikula::prelude::Term::Match(resource) => f(resource),
        sikula::prelude::Term::Not(term) => {
            let query_terms = vec![(Occur::MustNot, term2query(term, f))];
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
pub fn create_date_query(field: Field, value: &Ordered<time::OffsetDateTime>) -> Box<dyn Query> {
    match value {
        Ordered::Less(e) => Box::new(RangeQuery::new_term_bounds(
            field,
            Type::Date,
            &Bound::Unbounded,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::LessEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field,
            Type::Date,
            &Bound::Unbounded,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
        )),
        Ordered::Greater(e) => Box::new(RangeQuery::new_term_bounds(
            field,
            Type::Date,
            &Bound::Excluded(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::GreaterEqual(e) => Box::new(RangeQuery::new_term_bounds(
            field,
            Type::Date,
            &Bound::Included(Term::from_field_date(field, DateTime::from_utc(*e))),
            &Bound::Unbounded,
        )),
        Ordered::Equal(e) => Box::new(BooleanQuery::new(vec![(
            Occur::Must,
            Box::new(TermQuery::new(
                Term::from_field_date(field, DateTime::from_utc(*e)),
                Default::default(),
            )),
        )])),
        Ordered::Range(from, to) => {
            let from = bound_map(*from, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            let to = bound_map(*to, |f| Term::from_field_date(field, DateTime::from_utc(f)));
            Box::new(RangeQuery::new_term_bounds(field, Type::Date, &from, &to))
        }
    }
}

/// Convert a sikula primary to a tantivy Occur
pub fn primary2occur<'m>(primary: &Primary<'m>) -> (Occur, &'m str) {
    match primary {
        Primary::Equal(value) => (Occur::Must, value),
        Primary::Partial(value) => (Occur::Should, value),
    }
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
