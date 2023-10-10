use core::str::FromStr;
use cve::{common, Cve, Published, Rejected, Timestamp};
use cvss::v3::Base;
use sikula::prelude::*;
use tantivy::{
    collector::TopDocs, query::AllQuery, schema::INDEXED, store::ZstdCompressor, DocAddress, IndexSettings, Order,
    Searcher,
};
use time::OffsetDateTime;
use trustification_api::search::SearchOptions;
use trustification_index::{
    create_boolean_query, create_date_query, create_float_query, create_string_query, field2bool, field2date_opt,
    field2str, field2strvec,
    metadata::doc2metadata,
    sort_by,
    tantivy::{
        doc,
        query::{Occur, Query},
        schema::{Field, Schema, Term, FAST, STORED, STRING, TEXT},
        DateTime,
    },
    term2query, Document, Error as SearchError,
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
            indexed_timestamp: schema.add_date_field("indexed_timestamp", STORED),
            id: schema.add_text_field("id", STRING | FAST | STORED),
            published: schema.add_bool_field("published", FAST | INDEXED | STORED),

            assigner_short_name: schema.add_text_field("assigner_short_name", STRING | STORED),
            date_reserved: schema.add_date_field("date_reserved", INDEXED),
            date_published: schema.add_date_field("date_published", INDEXED | FAST | STORED),
            date_updated: schema.add_date_field("date_updated", INDEXED | FAST | STORED),
            date_rejected: schema.add_date_field("date_rejected", INDEXED | FAST | STORED),

            title: schema.add_text_field("title", TEXT | FAST | STORED),
            description: schema.add_text_field("description", TEXT | FAST | STORED),

            cvss3x_score: schema.add_f64_field("cvss3x_score", FAST | INDEXED | STORED),
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

    fn index_published_cve(&self, cve: &Published) -> Result<Document, SearchError> {
        log::debug!("Indexing published CVE document");

        let mut document = doc!();

        document.add_text(self.fields.published, true);
        self.index_common(&mut document, &cve.metadata.common, &cve.containers.cna.common);

        if let Some(title) = &cve.containers.cna.title {
            document.add_text(self.fields.title, title);
        }

        for desc in &cve.containers.cna.descriptions {
            document.add_text(self.fields.description, &desc.value);
        }

        for metric in &cve.containers.cna.metrics {
            if let Some(score) = metric.cvss_v3_1.as_ref().and_then(|v| v["vectorString"].as_str()) {
                match Base::from_str(score) {
                    Ok(score) => document.add_f64(self.fields.cvss3x_score, score.score().value()),
                    Err(err) => log::warn!("Failed to parse CVSS 3.1: {err}"),
                }
            } else if let Some(score) = metric.cvss_v3_0.as_ref().and_then(|v| v["vectorString"].as_str()) {
                match Base::from_str(score) {
                    Ok(score) => document.add_f64(self.fields.cvss3x_score, score.score().value()),
                    Err(err) => log::warn!("Failed to parse CVSS 3.0: {err}"),
                }
            }
        }

        log::debug!("Indexed {:?}", document);
        Ok(document)
    }

    fn index_rejected_cve(&self, cve: &Rejected) -> Result<Document, SearchError> {
        log::debug!("Indexing rejected CVE document");

        let mut document = doc!();

        document.add_text(self.fields.published, false);
        self.index_common(&mut document, &cve.metadata.common, &cve.containers.cna.common);

        Self::add_timestamp(&mut document, self.fields.date_rejected, cve.metadata.date_rejected);

        log::debug!("Indexed {:?}", document);
        Ok(document)
    }

    fn resource2query(&self, resource: &Cves) -> Box<dyn Query> {
        match resource {
            Cves::Id(value) => create_string_query(self.fields.id, value),
            Cves::Title(value) => create_string_query(self.fields.title, value),
            Cves::Description(value) => create_string_query(self.fields.description, value),

            Cves::Score(value) => create_float_query(&self.schema, [self.fields.cvss3x_score], value),

            Cves::DateReserved(value) => create_date_query(&self.schema, self.fields.date_reserved, value),
            Cves::DatePublished(value) => create_date_query(&self.schema, self.fields.date_published, value),
            Cves::DateUpdated(value) => create_date_query(&self.schema, self.fields.date_updated, value),
            Cves::DateRejected(value) => create_date_query(&self.schema, self.fields.date_rejected, value),

            Cves::Published => create_boolean_query(Occur::Should, Term::from_field_bool(self.fields.published, true)),
            Cves::Rejected => create_boolean_query(Occur::Should, Term::from_field_bool(self.fields.published, false)),
        }
    }

    fn add_timestamp(document: &mut Document, field: Field, timestamp: impl Into<Option<Timestamp>>) {
        if let Some(timestamp) = timestamp.into() {
            // by definition, timestamps without timezone are considered UTC
            document.add_date(field, DateTime::from_utc(timestamp.assume_utc()))
        }
    }
}

#[derive(Debug)]
pub struct CveQuery {
    query: Box<dyn Query>,
    sort_by: Option<(Field, Order)>,
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchHit;
    type Document = Cve;
    type QueryContext = CveQuery;

    fn index_doc(&self, _id: &str, doc: &Cve) -> Result<Document, SearchError> {
        match doc {
            Cve::Published(cve) => self.index_published_cve(cve),
            Cve::Rejected(cve) => self.index_rejected_cve(cve),
        }
    }

    fn parse_doc(data: &[u8]) -> Result<Cve, SearchError> {
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
            .unwrap()
    }

    fn prepare_query(&self, q: &str) -> Result<CveQuery, SearchError> {
        let mut query = Cves::parse(q).map_err(|err| SearchError::QueryParser(err.to_string()))?;
        query.term = query.term.compact();

        log::debug!("Query: {:?}", query.term);

        let sort_by = query.sorting.first().map(|f| match f.qualifier {
            CvesSortable::Id => sort_by(f.direction, self.fields.id),
            CvesSortable::Score => sort_by(f.direction, self.fields.cvss3x_score),
            CvesSortable::DatePublished => sort_by(f.direction, self.fields.date_published),
            CvesSortable::DateUpdated => sort_by(f.direction, self.fields.date_updated),
            CvesSortable::DateRejected => sort_by(f.direction, self.fields.date_rejected),
        });

        let query = if query.term.is_empty() {
            Box::new(AllQuery)
        } else {
            term2query(&query.term, &|resource| self.resource2query(resource))
        };

        log::debug!("Processed query: {:?}", query);
        Ok(CveQuery { query, sort_by })
    }

    fn search(
        &self,
        searcher: &Searcher,
        query: &CveQuery,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<(f32, DocAddress)>, usize), SearchError> {
        if let Some((field, order)) = &query.sort_by {
            let order_by = self.schema.get_field_name(*field);
            let mut hits = Vec::new();
            let result = searcher.search(
                &query.query,
                &(
                    TopDocs::with_limit(limit)
                        .and_offset(offset)
                        .order_by_fast_field::<DateTime>(order_by, order.clone()),
                    tantivy::collector::Count,
                ),
            )?;
            for r in result.0 {
                hits.push((1.0, r.1));
            }
            Ok((hits, result.1))
        } else {
            Ok(searcher.search(
                &query.query,
                &(TopDocs::with_limit(limit).and_offset(offset), tantivy::collector::Count),
            )?)
        }
    }

    fn process_hit(
        &self,
        doc_address: DocAddress,
        score: f32,
        searcher: &Searcher,
        query: &CveQuery,
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

        let document = SearchDocument {
            id: id.to_string(),
            title: title.map(ToString::to_string),
            descriptions,
            published,
            cvss3x_score,

            date_published,
            date_updated,
        };

        let explanation: Option<serde_json::Value> = if options.explain {
            match query.query.explain(searcher, doc_address) {
                Ok(explanation) => Some(serde_json::to_value(explanation).ok()).unwrap_or(None),
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
