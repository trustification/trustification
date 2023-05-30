mod search;

use search::*;

use csaf::{definitions::NoteCategory, Csaf};
use sikula::prelude::*;
use std::fmt::Display;
use std::path::PathBuf;
use tantivy::collector::Count;
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
use tantivy::directory::INDEX_WRITER_LOCK;
use tantivy::doc;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{Term, *};
use tantivy::Directory;
use tantivy::Index as SearchIndex;
use tantivy::IndexWriter;
use tracing::info;

pub struct Index {
    index: SearchIndex,
    path: Option<PathBuf>,
    fields: Fields,
}

pub struct Fields {
    id: Field,
    title: Field,
    description: Field,
    cve: Field,
    severity: Field,
    status: Field,
    packages: Field,
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
        let status = match &csaf.document.tracking.status {
            csaf::document::Status::Draft => "draft",
            csaf::document::Status::Interim => "interim",
            csaf::document::Status::Final => "final",
        };

        if let Some(vulns) = &csaf.vulnerabilities {
            for vuln in vulns {
                let mut title = String::new();
                let mut description = String::new();
                let mut packages: Vec<String> = Vec::new();
                let mut cve = String::new();
                let mut severity = String::new();

                if let Some(t) = &vuln.title {
                    title = t.clone();
                }

                if let Some(c) = &vuln.cve {
                    cve = c.clone();
                }

                if let Some(scores) = &vuln.scores {
                    for score in scores {
                        if let Some(cvss3) = &score.cvss_v3 {
                            severity = cvss3.severity().as_str().to_string();
                            break;
                        }
                    }
                }

                if let Some(status) = &vuln.product_status {
                    if let Some(products) = &status.known_affected {
                        for product in products {
                            packages.push(product.0.clone());
                        }
                    }
                }
                let packages = packages.join(" ");

                if let Some(notes) = &vuln.notes {
                    for note in notes {
                        if let NoteCategory::Description = note.category {
                            description = note.text.clone();
                            break;
                        }
                    }

                    tracing::debug!(
                        "Indexing with id {} title {} description {}, cve {}, packages {}",
                        id,
                        title,
                        description,
                        cve,
                        packages
                    );
                    let document = doc!(
                        index.fields.id => id.as_str(),
                        index.fields.title => title,
                        index.fields.description => description,
                        index.fields.packages => packages,
                        index.fields.cve => cve,
                        index.fields.status => status,
                        index.fields.severity => severity,
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
        let title = schema.add_text_field("title", TEXT);
        let description = schema.add_text_field("description", TEXT);
        let cve = schema.add_text_field("cve", STRING | FAST | STORED);
        let severity = schema.add_text_field("severity", STRING | FAST);
        let status = schema.add_text_field("status", STRING);
        let packages = schema.add_text_field("packages", STRING);
        (
            schema.build(),
            Fields {
                id,
                title,
                description,
                cve,
                severity,
                status,
                packages,
            },
        )
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
        let dir = MmapDirectory::open(path).map_err(|_e| Error::Open)?;
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
            self.index.directory_mut().sync_directory().map_err(Error::Io)?;
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

    pub fn search(&self, q: &str, offset: usize, len: usize) -> Result<Vec<String>, Error> {
        let mut query = Vulnerabilities::parse_query(&q).map_err(|err| Error::Parser(err.to_string()))?;

        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        query.term = query.term.compact();

        info!("Query: {query:?}");

        let query = self.term2query(&query.term);

        info!("Processed query: {:?}", query);

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

    fn resource2query<'m>(&self, resource: &Vulnerabilities<'m>) -> Box<dyn Query> {
        let (occur, term) = match resource {
            Vulnerabilities::Id(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.id, value);
                (occur, term)
            }

            Vulnerabilities::Cve(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve, value);
                (occur, term)
            }

            Vulnerabilities::Description(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.description, value);
                (occur, term)
            }

            Vulnerabilities::Title(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.title, value);
                (occur, term)
            }

            Vulnerabilities::Severity(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.severity, value);
                (occur, term)
            }

            Vulnerabilities::Status(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.status, value);
                (occur, term)
            }

            Vulnerabilities::Final => (Occur::Must, Term::from_field_text(self.fields.status, "final")),

            Vulnerabilities::Critical => (Occur::Must, Term::from_field_text(self.fields.severity, "critical")),
            Vulnerabilities::High => (Occur::Must, Term::from_field_text(self.fields.severity, "high")),
            Vulnerabilities::Medium => (Occur::Must, Term::from_field_text(self.fields.severity, "medium")),
            Vulnerabilities::Low => (Occur::Must, Term::from_field_text(self.fields.severity, "low")),
        };

        Box::new(BooleanQuery::new(vec![(
            occur,
            Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
        )]))
    }

    fn term2query<'m>(&self, term: &sikula::prelude::Term<'m, Vulnerabilities<'m>>) -> Box<dyn Query> {
        match term {
            sikula::prelude::Term::Match(resource) => self.resource2query(resource),
            sikula::prelude::Term::Not(term) => {
                let query_terms = vec![(Occur::MustNot, self.term2query(&term))];
                let query = BooleanQuery::new(query_terms);
                Box::new(query)
            }
            sikula::prelude::Term::And(terms) => {
                let mut query_terms = Vec::new();
                for term in terms {
                    query_terms.push(self.term2query(&term));
                }
                Box::new(BooleanQuery::intersection(query_terms))
            }
            sikula::prelude::Term::Or(terms) => {
                let mut query_terms = Vec::new();
                for term in terms {
                    query_terms.push(self.term2query(&term));
                }
                Box::new(BooleanQuery::union(query_terms))
            }
        }
    }
}

fn primary2occur<'m>(primary: &Primary<'m>) -> (Occur, &'m str) {
    match primary {
        Primary::Equal(value) => (Occur::Must, value),
        Primary::Partial(value) => (Occur::Should, value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_free_form<F>(f: F)
    where
        F: FnOnce(Index),
    {
        let _ = env_logger::try_init();

        let data = std::fs::read_to_string("../testdata/rhsa-2023_1441.json").unwrap();
        let csaf: Csaf = serde_json::from_str(&data).unwrap();
        let mut index = Index::new_in_memory().unwrap();
        let mut writer = index.indexer().unwrap();
        writer.index(&mut index, &csaf).unwrap();
        writer.commit().unwrap();
        f(index);
    }

    #[tokio::test]
    async fn test_free_form_simple_primary() {
        assert_free_form(|index| {
            let result = index.search("openssl", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_2() {
        assert_free_form(|index| {
            let result = index.search("CVE-2023-0286", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_3() {
        assert_free_form(|index| {
            let result = index.search("RHSA-2023:1441", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_primary_scoped() {
        assert_free_form(|index| {
            let result = index.search("RHSA-2023:1441 in:id", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_final() {
        assert_free_form(|index| {
            let result = index.search("is:final", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_high() {
        assert_free_form(|index| {
            let result = index.search("is:high", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_critical() {
        assert_free_form(|index| {
            let result = index.search("is:critical", 0, 100).unwrap();
            assert_eq!(result.len(), 0);
        });
    }
}
