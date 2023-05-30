mod search;

use search::*;

use csaf::{definitions::NoteCategory, Csaf};
use sikula::prelude::*;
use std::fmt::{write, Display};
use std::path::PathBuf;
use tantivy::collector::Count;
use tantivy::collector::TopDocs;
use tantivy::directory::DirectoryLock;
use tantivy::directory::MmapDirectory;
use tantivy::directory::INDEX_WRITER_LOCK;
use tantivy::doc;
use tantivy::merge_policy::LogMergePolicy;
use tantivy::query::{TermQuery, TermSetQuery};
use tantivy::schema::{Term, *};
use tantivy::Directory;
use tantivy::Index as SearchIndex;
use tantivy::IndexWriter;
use tracing::{info, warn};

pub struct Index {
    index: SearchIndex,
    path: Option<PathBuf>,
    fields: Fields,
}

pub struct Fields {
    id: Field,
    description: Field,
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
    pub fn index(&mut self, index: &mut Index, csaf: &Csaf) -> Result<(), Error> {
        let id = &csaf.document.tracking.id;
        if let Some(vulns) = &csaf.vulnerabilities {
            for vuln in vulns {
                let mut description = String::new();
                if let Some(notes) = &vuln.notes {
                    for note in notes {
                        if let NoteCategory::Description = note.category {
                            description = note.text.clone();
                            break;
                        }
                    }

                    info!("Indexing with id {} description {}", id, description);
                    let document = doc!(
                        index.fields.id => id.as_str(),
                        index.fields.description => description,
                    );

                    self.writer.add_document(document)?;
                }
            }
        }
        Ok(())
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.writer.commit()?;
        self.writer.wait_merging_threads()?;
        Ok(())
    }
}

impl Index {
    fn schema() -> (Schema, Fields) {
        let mut schema = Schema::builder();
        let id = schema.add_text_field("id", STRING | FAST | STORED);
        let description = schema.add_text_field("description", TEXT);
        (schema.build(), Fields { id, description })
    }

    pub fn new_in_memory() -> Result<Self, Error> {
        let (schema, fields) = Self::schema();
        let index = SearchIndex::create_in_ram(schema);
        Ok(Self {
            index,
            path: None,
            fields,
        })
    }

    pub fn new(path: &PathBuf) -> Result<Self, Error> {
        let (schema, fields) = Self::schema();
        let dir = MmapDirectory::open(path).map_err(|e| Error::Open)?;
        let index = SearchIndex::open_or_create(dir, schema)?;
        Ok(Self {
            index,
            path: Some(path.clone()),
            fields,
        })
    }

    pub fn restore(path: &PathBuf, data: &[u8]) -> Result<Self, Error> {
        let dec = zstd::stream::Decoder::new(data).map_err(Error::Io)?;
        let mut archive = tar::Archive::new(dec);
        archive.unpack(path).map_err(Error::Io)?;
        Self::new(path)
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
            let lock = self.index.directory_mut().sync_directory().map_err(Error::Io)?;
            let lock = self.index.directory_mut().acquire_lock(&INDEX_WRITER_LOCK);

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
        let writer = self.index.writer(100_000_000)?;
        Ok(Indexer { writer })
    }

    pub fn search_x(
        &self,
        query: &str,
        fields: &[&str],
        filters: &[(&str, &str)],
        offset: usize,
        len: usize,
    ) -> Result<Vec<String>, Error> {
        let schema = self.index.schema();
        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        let mut terms = vec![];
        for field in schema.fields() {
            let field_name = field.1.name();
            if fields.is_empty() || fields.contains(&field_name) {
                terms.push(Term::from_field_text(field.0, query));
            }
        }

        let query = TermSetQuery::new(terms);

        let (top_docs, count) = searcher.search(&query, &(TopDocs::with_limit(len).and_offset(offset), Count))?;

        tracing::trace!("Found {} docs", count);

        let mut hits = Vec::new();
        for hit in top_docs {
            let doc = searcher.doc(hit.1)?;
            if let Some(Some(value)) = doc.get_first(self.fields.id).map(|s| s.as_text()) {
                hits.push(value.into());
            }
        }

        tracing::trace!("Filtered to {}", hits.len());

        Ok(hits)
    }

    pub fn search(
        &self,
        q: &str,
        fields: &[&str],
        filters: &[(&str, &str)],
        offset: usize,
        len: usize,
    ) -> Result<Vec<String>, Error> {
        let mut query = Vulnerabilities::parse_query(&q).map_err(|err| Error::Parser(err.to_string()))?;

        let schema = self.index.schema();
        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        query.term = query.term.compact();

        info!("Query: {query:?}");
        info!("Fields: {:?}", schema.fields().collect::<Vec<_>>());

        let mut terms = vec![];
        match query.term.compact() {
            sikula::prelude::Term::Match(Vulnerabilities::Id(Primary::Equal(value))) => {
                terms.push(Term::from_field_text(schema.get_field("id").unwrap(), value));
            }
            sikula::prelude::Term::Match(Vulnerabilities::Id(Primary::Partial(value))) => {
                terms.push(Term::from_field_text(schema.get_field("id").unwrap(), value));
            }
            sikula::prelude::Term::Match(Vulnerabilities::Description(Primary::Equal(value))) => {
                terms.push(Term::from_field_text(schema.get_field("description").unwrap(), value));
            }
            sikula::prelude::Term::Match(Vulnerabilities::Description(Primary::Partial(value))) => {
                terms.push(Term::from_field_text(schema.get_field("description").unwrap(), value));
            }
            n => {
                warn!("Ignoring search term: {n:?}");
            }
        }

        info!("Terms: {terms:?}");

        /*
        let mut terms = vec![];
        for field in schema.fields() {
            let field_name = field.1.name();
            if fields.is_empty() || fields.contains(&field_name) {
                terms.push(Term::from_field_text(field.0, q));
            }
        }*/

        let query = TermSetQuery::new(terms);

        let (top_docs, count) = searcher.search(&query, &(TopDocs::with_limit(len).and_offset(offset), Count))?;

        tracing::trace!("Found {} docs", count);

        let mut hits = Vec::new();
        for hit in top_docs {
            let doc = searcher.doc(hit.1)?;
            if let Some(Some(value)) = doc.get_first(self.fields.id).map(|s| s.as_text()) {
                hits.push(value.into());
            }
        }

        tracing::trace!("Filtered to {}", hits.len());

        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic() {
        env_logger::init();
        let data = std::fs::read_to_string("../testdata/rhsa-2023_1441.json").unwrap();
        let csaf: Csaf = serde_json::from_str(&data).unwrap();
        let mut index = Index::new_in_memory().unwrap();
        let mut writer = index.indexer().unwrap();
        writer.index(&mut index, &csaf).unwrap();
        writer.commit().unwrap();

        let result = index.search("openssl", &[], &[], 0, 100).unwrap();
        assert_eq!(result.len(), 1);
    }
}
