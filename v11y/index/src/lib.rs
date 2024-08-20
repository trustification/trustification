use core::str::FromStr;
pub use cve::Cve;
use cve::{common, Published, Rejected, Timestamp};
use cvss::v3::Base;
use cvss::Severity;
use serde_json::Value;
use sikula::prelude::*;
use std::time::Duration;
use time::OffsetDateTime;
use trustification_api::search::SearchOptions;
use trustification_index::{
    create_boolean_query, create_date_query, create_float_query, create_string_query_case, create_text_query,
    field2bool, field2date_opt, field2str, field2strvec,
    metadata::doc2metadata,
    sort_by,
    tantivy::{
        self,
        collector::TopDocs,
        doc,
        query::{AllQuery, Occur, Query, TermQuery},
        schema::{Field, Schema, Term, FAST, INDEXED, STORED, STRING, TEXT},
        store::ZstdCompressor,
        DateTime, DocAddress, DocId, IndexSettings, Score, Searcher, SegmentReader,
    },
    term2query, Case, Document, Error as SearchError, SearchQuery,
};
use v11y_model::search::{Cves, CvesSortable, SearchDocument, SearchHit};

pub struct Index {
    schema: Schema,
    fields: Fields,
}

struct Fields {
    indexed_timestamp: Field,

    id: Field,
    published: Field,

    date_reserved: Field,
    date_published: Field,
    date_updated: Field,
    date_rejected: Field,

    assigner_short_name: Field,

    title: Field,
    description: Field,

    cvss3x_score: Field,
    severity: Field,
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    pub fn new() -> Self {
        let mut schema = Schema::builder();

        let fields = Fields {
            indexed_timestamp: schema.add_date_field("indexed_timestamp", INDEXED | FAST | STORED),
            id: schema.add_text_field("id", STRING | FAST | STORED),
            published: schema.add_bool_field("published", FAST | INDEXED | STORED),

            assigner_short_name: schema.add_text_field("assigner_short_name", STRING | STORED),
            date_reserved: schema.add_date_field("date_reserved", INDEXED),
            date_published: schema.add_date_field("date_published", INDEXED | FAST | STORED),
            date_updated: schema.add_date_field("date_updated", INDEXED | FAST | STORED),
            date_rejected: schema.add_date_field("date_rejected", INDEXED | FAST | STORED),

            title: schema.add_text_field("title", TEXT | STORED),
            description: schema.add_text_field("description", TEXT | STORED),

            cvss3x_score: schema.add_f64_field("cvss3x_score", FAST | INDEXED | STORED),
            severity: schema.add_text_field("severity", STRING | FAST),
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_common(&self, document: &mut Document, metadata: &common::Metadata, _container: &common::CnaContainer) {
        document.add_text(self.fields.id, &metadata.id);

        document.add_date(
            self.fields.indexed_timestamp,
            DateTime::from_utc(OffsetDateTime::now_utc()),
        );

        Self::add_timestamp(document, self.fields.date_reserved, metadata.date_reserved);
        Self::add_timestamp(document, self.fields.date_published, metadata.date_published);
        Self::add_timestamp(document, self.fields.date_updated, metadata.date_updated);

        if let Some(short_name) = &metadata.assigner_short_name {
            document.add_text(self.fields.assigner_short_name, short_name);
        }
    }

    fn index_published_cve(&self, cve: &Published, _id: &str) -> Result<Vec<(String, Document)>, SearchError> {
        log::debug!("Indexing published CVE document");
        let mut documents: Vec<(String, Document)> = Vec::new();
        let mut document = doc!();

        document.add_bool(self.fields.published, true);
        self.index_common(&mut document, &cve.metadata.common, &cve.containers.cna.common);

        if let Some(title) = &cve.containers.cna.title {
            document.add_text(self.fields.title, title);
        }

        for desc in &cve.containers.cna.descriptions {
            document.add_text(self.fields.description, &desc.value);
        }

        fn parse_score(score: &Value, version: &str) -> Option<Base> {
            let score = score["vectorString"].as_str()?;

            match Base::from_str(score) {
                Ok(score) => Some(score),
                Err(err) => {
                    log::warn!("Failed to parse CVSS {version} ({score}): {err}");
                    None
                }
            }
        }

        for metric in &cve.containers.cna.metrics {
            let score = metric
                .cvss_v3_1
                .as_ref()
                .and_then(|score| parse_score(score, "3.1"))
                .or_else(|| metric.cvss_v3_0.as_ref().and_then(|score| parse_score(score, "3.0")));

            if let Some(score) = score {
                document.add_f64(self.fields.cvss3x_score, score.score().value());
                document.add_text(self.fields.severity, score.severity().to_string());
            }
        }

        log::debug!("Indexed {:?}", document);
        documents.push((_id.to_string(), document));
        Ok(documents)
    }

    fn index_rejected_cve(&self, cve: &Rejected, _id: &str) -> Result<Vec<(String, Document)>, SearchError> {
        log::debug!("Indexing rejected CVE document");
        let mut documents: Vec<(String, Document)> = Vec::new();
        let mut document = doc!();

        document.add_bool(self.fields.published, false);
        self.index_common(&mut document, &cve.metadata.common, &cve.containers.cna.common);

        Self::add_timestamp(&mut document, self.fields.date_rejected, cve.metadata.date_rejected);

        for desc in &cve.containers.cna.rejected_reasons {
            document.add_text(self.fields.description, &desc.value);
        }

        log::debug!("Indexed {:?}", document);
        documents.push((_id.to_string(), document));
        Ok(documents)
    }

    fn resource2query(&self, resource: &Cves) -> Box<dyn Query> {
        match resource {
            Cves::Id(value) => create_string_query_case(self.fields.id, value, Case::Uppercase),

            // TODO: consider boosting the title
            Cves::Title(value) => create_text_query(self.fields.title, value),
            Cves::Description(value) => create_text_query(self.fields.description, value),

            Cves::Score(value) => create_float_query(&self.schema, [self.fields.cvss3x_score], value),

            Cves::DateReserved(value) => create_date_query(&self.schema, self.fields.date_reserved, value),
            Cves::DatePublished(value) => create_date_query(&self.schema, self.fields.date_published, value),
            Cves::DateUpdated(value) => create_date_query(&self.schema, self.fields.date_updated, value),
            Cves::DateRejected(value) => create_date_query(&self.schema, self.fields.date_rejected, value),

            Cves::Published => create_boolean_query(Occur::Should, Term::from_field_bool(self.fields.published, true)),
            Cves::Rejected => create_boolean_query(Occur::Should, Term::from_field_bool(self.fields.published, false)),

            Cves::Severity(value) => Box::new(TermQuery::new(
                Term::from_field_text(self.fields.severity, value),
                Default::default(),
            )),
            Cves::Low => create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.severity, Severity::Low.as_str()),
            ),
            Cves::Medium => create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.severity, Severity::Medium.as_str()),
            ),
            Cves::High => create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.severity, Severity::High.as_str()),
            ),
            Cves::Critical => create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.severity, Severity::Critical.as_str()),
            ),
            Cves::IndexedTimestamp(value) => create_date_query(&self.schema, self.fields.indexed_timestamp, value),
        }
    }

    fn add_timestamp(document: &mut Document, field: Field, timestamp: impl Into<Option<Timestamp>>) {
        if let Some(timestamp) = timestamp.into() {
            // by definition, timestamps without timezone are considered UTC
            document.add_date(field, DateTime::from_utc(timestamp.assume_utc()))
        }
    }
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchHit<SearchDocument>;

    fn prepare_query(&self, q: &str) -> Result<SearchQuery, SearchError> {
        let mut query = Cves::parse(q).map_err(|err| SearchError::QueryParser(err.to_string()))?;
        query.term = query.term.compact();

        log::debug!("Query: {:?}", query.term);

        let sort_by = query.sorting.first().map(|f| match f.qualifier {
            CvesSortable::Score => sort_by(f.direction, self.fields.cvss3x_score),
            CvesSortable::DatePublished => sort_by(f.direction, self.fields.date_published),
            CvesSortable::DateUpdated => sort_by(f.direction, self.fields.date_updated),
            CvesSortable::DateRejected => sort_by(f.direction, self.fields.date_rejected),
            CvesSortable::IndexedTimestamp => sort_by(f.direction, self.fields.indexed_timestamp),
        });

        let query = if query.term.is_empty() {
            Box::new(AllQuery)
        } else {
            term2query(&query.term, &|resource| self.resource2query(resource))
        };

        log::trace!("Processed query: {:?}", query);
        Ok(SearchQuery { query, sort_by })
    }

    fn search(
        &self,
        searcher: &Searcher,
        query: &dyn Query,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<(f32, DocAddress)>, usize), SearchError> {
        let severity_field = self.schema.get_field_name(self.fields.cvss3x_score).to_string();
        let date_field = self.schema.get_field_name(self.fields.date_updated).to_string();
        let now = tantivy::DateTime::from_utc(OffsetDateTime::now_utc());
        Ok(searcher.search(
            query,
            &(
                TopDocs::with_limit(limit)
                    .and_offset(offset)
                    .tweak_score(move |segment_reader: &SegmentReader| {
                        let severity_reader = segment_reader.fast_fields().f64(&severity_field);

                        let date_reader = segment_reader.fast_fields().date(&date_field);

                        move |doc: DocId, original_score: Score| {
                            let severity_reader = severity_reader.clone();
                            let date_reader = date_reader.clone();
                            let mut tweaked = original_score;
                            if let Ok(Some(score)) = severity_reader.map(|s| s.first(doc)) {
                                log::trace!("CVSS score impact {} -> {}", tweaked, (score as f32) * tweaked);
                                tweaked *= score as f32;

                                // Now look at the date, normalize score between 0 and 1 (baseline 1970)
                                if let Ok(Some(date)) = date_reader.map(|s| s.first(doc)) {
                                    if date < now {
                                        let mut normalized = 2.0
                                            * (date.into_timestamp_secs() as f64 / now.into_timestamp_secs() as f64);
                                        // If it's the past month, boost it more.
                                        if (now.into_utc() - date.into_utc()) < Duration::from_secs(30 * 24 * 3600) {
                                            normalized *= 4.0;
                                        }
                                        log::trace!(
                                            "DATE score impact {} -> {}",
                                            tweaked,
                                            tweaked * (normalized as f32)
                                        );
                                        tweaked *= normalized as f32;
                                    }
                                }
                            }
                            log::trace!("Tweaking from {} to {}", original_score, tweaked);
                            tweaked
                        }
                    }),
                tantivy::collector::Count,
            ),
        )?)
    }

    fn process_hit(
        &self,
        doc_address: DocAddress,
        score: f32,
        searcher: &Searcher,
        query: &dyn Query,
        options: &SearchOptions,
    ) -> Result<Self::MatchedDocument, SearchError> {
        let doc = searcher.doc(doc_address)?;

        let id = field2str(&self.schema, &doc, self.fields.id)?;
        let title = doc.get_first(self.fields.title).and_then(|s| s.as_text());
        let published = field2bool(&self.schema, &doc, self.fields.published)?;
        let descriptions = field2strvec(&doc, self.fields.description)?
            .iter()
            .map(|s| s.to_string())
            .collect();

        let cvss3x_score = doc.get_first(self.fields.cvss3x_score).and_then(|s| s.as_f64());

        let date_published = field2date_opt(&doc, self.fields.date_published);
        let date_updated = field2date_opt(&doc, self.fields.date_updated);
        let indexed_timestamp = doc
            .get_first(self.fields.indexed_timestamp)
            .map(|s| {
                s.as_date()
                    .map(|d| d.into_utc())
                    .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            })
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let document = SearchDocument {
            id: id.to_string(),
            title: title.map(ToString::to_string),
            descriptions,
            published,
            cvss3x_score,

            date_published,
            date_updated,
            indexed_timestamp,
        };

        let explanation: Option<Value> = if options.explain {
            match query.explain(searcher, doc_address) {
                Ok(explanation) => serde_json::to_value(explanation).ok(),
                Err(e) => {
                    log::warn!("Error producing explanation for document {:?}: {:?}", doc_address, e);
                    None
                }
            }
        } else {
            None
        };

        let metadata = options.metadata.then(|| doc2metadata(&self.schema, &doc));

        Ok(SearchHit {
            document,
            score,
            explanation,
            metadata,
        })
    }
}

impl trustification_index::WriteIndex for Index {
    type Document = Cve;

    fn name(&self) -> &str {
        "cve"
    }

    fn index_doc(&self, id: &str, doc: &Cve) -> Result<Vec<(String, Document)>, SearchError> {
        match doc {
            Cve::Published(cve) => self.index_published_cve(cve, id),
            Cve::Rejected(cve) => self.index_rejected_cve(cve, id),
        }
    }

    fn parse_doc(&self, data: &[u8]) -> Result<Cve, SearchError> {
        serde_json::from_slice(data).map_err(|err| SearchError::DocParser(err.to_string()))
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn settings(&self) -> IndexSettings {
        IndexSettings {
            docstore_compression: tantivy::store::Compressor::Zstd(ZstdCompressor::default()),
            ..Default::default()
        }
    }

    fn doc_id_to_term(&self, id: &str) -> Term {
        self.schema
            .get_field("id")
            .map(|f| Term::from_field_text(f, id))
            .expect("the document schema defines this field")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;
    use trustification_index::{IndexStore, IndexWriter};

    const TESTDATA: &[&str] = &["../testdata/CVE-2023-44487.json"];

    fn load_valid_file(store: &mut IndexStore<Index>, writer: &mut IndexWriter, path: impl AsRef<Path>) {
        let data = std::fs::read(&path).unwrap();
        // ensure it parses
        serde_json::from_slice::<Cve>(&data)
            .unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display()));
        let name = path.as_ref().file_name().unwrap().to_str().unwrap();
        let name = name.rsplit_once('.').unwrap().0;
        // add to index
        writer.add_document(store.index_as_mut(), name, &data).unwrap();
    }

    fn assert_search<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        let _ = env_logger::try_init();

        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();
        let mut writer = store.writer().unwrap();

        for file in TESTDATA {
            load_valid_file(&mut store, &mut writer, file);
        }

        writer.commit().unwrap();

        f(store);
    }

    fn search(index: &IndexStore<Index>, query: &str) -> (Vec<SearchHit<SearchDocument>>, usize) {
        index
            .search(
                query,
                0,
                10000,
                SearchOptions {
                    metadata: false,
                    explain: false,
                    summaries: true,
                },
            )
            .unwrap()
    }

    #[tokio::test]
    async fn test_by_id() {
        assert_search(|index| {
            let result = search(&index, r#"id:"CVE-2023-44487""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_by_id_lowercase() {
        assert_search(|index| {
            let result = search(&index, r#"id:"cve-2023-44487""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_id() {
        assert_search(|index| {
            let result = search(&index, r#"in:id "CVE-2023-44487""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_id_lowercase() {
        assert_search(|index| {
            let result = search(&index, r#"in:id "cve-2023-44487""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test() {
        assert_search(|index| {
            let result = search(&index, r#"allow in:description"#);
            assert_eq!(result.0.len(), 1);
        });

        assert_search(|index| {
            let result = search(&index, r#"in:description 2023"#);
            assert_eq!(result.0.len(), 1);
        });

        assert_search(|index| {
            let result = search(&index, r#"in:description Octob"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_description() {
        assert_search(|index| {
            let result = search(&index, r#"in:description October 2023"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_description_lowercase() {
        assert_search(|index| {
            let result = search(&index, r#"in:description october 2023"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_description_special() {
        assert_search(|index| {
            let result = search(&index, r#"in:description "HTTP/2""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_in_description_special_lowercase() {
        assert_search(|index| {
            let result = search(&index, r#"in:description "http/2""#);
            assert_eq!(result.0.len(), 1);
        });
    }
}
