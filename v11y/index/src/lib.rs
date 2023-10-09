use core::str::FromStr;
use cve::{published, Cve, Published, Rejected};
use sikula::{mir::Direction, prelude::*};
use tantivy::{
    collector::TopDocs,
    query::{AllQuery, BooleanQuery, TermQuery, TermSetQuery},
    schema::INDEXED,
    store::ZstdCompressor,
    DocAddress, IndexSettings, Order, Searcher, SnippetGenerator,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use trustification_api::search::SearchOptions;
use trustification_index::{
    boost, create_boolean_query, create_date_query, create_string_query, field2str,
    metadata::doc2metadata,
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
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_published_cve(&self, cve: &Published) -> Result<Document, SearchError> {
        log::debug!("Indexing published CVE document");

        let mut document = doc!();

        document.add_text(self.fields.id, &cve.metadata.id);

        log::debug!("Indexed {:?}", document);
        Ok(document)
    }

    fn index_rejected_cve(&self, cve: &Rejected) -> Result<Document, SearchError> {
        log::debug!("Indexing rejected CVE document");

        let mut document = doc!();

        document.add_text(self.fields.id, &cve.metadata.id);

        log::debug!("Indexed {:?}", document);
        Ok(document)
    }

    fn resource2query(&self, resource: &Cves) -> Box<dyn Query> {
        const PACKAGE_WEIGHT: f32 = 1.5;
        const CREATED_WEIGHT: f32 = 1.25;
        match resource {
            Cves::Id(value) => Box::new(TermQuery::new(
                Term::from_field_text(self.fields.id, value),
                Default::default(),
            )),
        }
    }

    fn create_string_query(&self, fields: &[Field], value: &Primary<'_>) -> Box<dyn Query> {
        let queries: Vec<Box<dyn Query>> = fields.iter().map(|f| create_string_query(*f, value)).collect();
        Box::new(BooleanQuery::union(queries))
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

        let mut sort_by = None;
        if let Some(f) = query.sorting.first() {
            match f.qualifier {
                CvesSortable::Id => match f.direction {
                    Direction::Descending => {
                        sort_by.replace((self.fields.id, Order::Desc));
                    }
                    Direction::Ascending => {
                        sort_by.replace((self.fields.id, Order::Asc));
                    }
                },
            }
        }

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
                        .order_by_fast_field::<tantivy::DateTime>(order_by, order.clone()),
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

        let document = SearchDocument { id: id.to_string() };

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
