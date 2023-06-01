mod search;

use search::*;

use csaf::{definitions::NoteCategory, Csaf};
use sikula::prelude::*;

use std::ops::Bound;

use tracing::info;
use trustification_index::{
    tantivy::query::{BooleanQuery, Occur, Query, RangeQuery, TermQuery},
    tantivy::schema::{Field, IndexRecordOption, Schema, Term, Type, FAST, INDEXED, STORED, STRING, TEXT},
    tantivy::{doc, DateTime},
    Document, Error as SearchError,
};

pub struct Index {
    schema: Schema,
    fields: Fields,
}

struct Fields {
    id: Field,
    title: Field,
    description: Field,
    cve: Field,
    advisory_initial: Field,
    advisory_current: Field,
    cve_release: Field,
    cve_discovery: Field,
    severity: Field,
    cvss: Field,
    status: Field,
    packages: Field,
}

impl trustification_index::Index for Index {
    type DocId = String;
    type Document = Csaf;

    fn index_doc(&self, csaf: &Csaf) -> Result<Vec<Document>, SearchError> {
        let mut documents = Vec::new();
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

                let mut score_value = 0.0;
                if let Some(scores) = &vuln.scores {
                    for score in scores {
                        if let Some(cvss3) = &score.cvss_v3 {
                            severity = cvss3.severity().as_str().to_string();
                            score_value = cvss3.score().value();
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
                        "Indexing with id {} title {} description {}, cve {}, packages {} score {}",
                        id,
                        title,
                        description,
                        cve,
                        packages,
                        score_value,
                    );
                    let mut document = doc!(
                        self.fields.id => id.as_str(),
                        self.fields.title => title,
                        self.fields.description => description,
                        self.fields.packages => packages,
                        self.fields.cve => cve,
                        self.fields.status => status,
                        self.fields.severity => severity,
                        self.fields.cvss => score_value,
                    );

                    document.add_date(
                        self.fields.advisory_initial,
                        DateTime::from_timestamp_millis(csaf.document.tracking.initial_release_date.timestamp_millis()),
                    );

                    document.add_date(
                        self.fields.advisory_current,
                        DateTime::from_timestamp_millis(csaf.document.tracking.current_release_date.timestamp_millis()),
                    );

                    if let Some(discovery_date) = &vuln.discovery_date {
                        document.add_date(
                            self.fields.cve_discovery,
                            DateTime::from_timestamp_millis(discovery_date.timestamp_millis()),
                        );
                    }

                    if let Some(release_date) = &vuln.release_date {
                        document.add_date(
                            self.fields.cve_release,
                            DateTime::from_timestamp_millis(release_date.timestamp_millis()),
                        );
                    }

                    documents.push(document);
                }
            }
        }
        Ok(documents)
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, SearchError> {
        let mut query = Vulnerabilities::parse_query(&q).map_err(|err| SearchError::Parser(err.to_string()))?;

        query.term = query.term.compact();

        info!("Query: {query:?}");

        let query = self.term2query(&query.term);

        info!("Processed query: {:?}", query);
        Ok(query)
    }

    fn process_hit(&self, doc: Document) -> Result<Self::DocId, SearchError> {
        if let Some(Some(value)) = doc.get_first(self.fields.id).map(|s| s.as_text()) {
            Ok(value.into())
        } else {
            Err(SearchError::NotFound)
        }
    }
}

impl Index {
    pub fn new() -> Self {
        let mut schema = Schema::builder();
        let id = schema.add_text_field("id", STRING | FAST | STORED);
        let title = schema.add_text_field("title", TEXT);
        let description = schema.add_text_field("description", TEXT);
        let cve = schema.add_text_field("cve", STRING | FAST | STORED);
        let severity = schema.add_text_field("severity", STRING | FAST);
        let status = schema.add_text_field("status", STRING);
        let cvss = schema.add_f64_field("cvss", FAST | INDEXED);
        let packages = schema.add_text_field("packages", STRING);
        let advisory_initial = schema.add_date_field("advisory_initial_date", INDEXED);
        let advisory_current = schema.add_date_field("advisory_current_date", INDEXED);
        let cve_discovery = schema.add_date_field("cve_discovery_date", INDEXED);
        let cve_release = schema.add_date_field("cve_release_date", INDEXED);
        Self {
            schema: schema.build(),
            fields: Fields {
                id,
                cvss,
                title,
                description,
                cve,
                severity,
                status,
                packages,
                advisory_initial,
                advisory_current,
                cve_discovery,
                cve_release,
            },
        }
    }

    fn resource2query<'m>(&self, resource: &Vulnerabilities<'m>) -> Box<dyn Query> {
        fn create_boolean(occur: Occur, term: Term) -> Box<dyn Query> {
            Box::new(BooleanQuery::new(vec![(
                occur,
                Box::new(TermQuery::new(term, IndexRecordOption::Basic)),
            )]))
        }

        match resource {
            Vulnerabilities::Id(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.id, value);
                create_boolean(occur, term)
            }

            Vulnerabilities::Cve(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve, value);
                create_boolean(occur, term)
            }

            Vulnerabilities::Description(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.description, value);
                create_boolean(occur, term)
            }

            Vulnerabilities::Title(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.title, value);
                create_boolean(occur, term)
            }

            Vulnerabilities::Severity(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.severity, value);
                create_boolean(occur, term)
            }

            Vulnerabilities::Status(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.status, value);
                create_boolean(occur, term)
            }
            Vulnerabilities::Final => create_boolean(Occur::Must, Term::from_field_text(self.fields.status, "final")),
            Vulnerabilities::Critical => {
                create_boolean(Occur::Must, Term::from_field_text(self.fields.severity, "critical"))
            }
            Vulnerabilities::High => create_boolean(Occur::Must, Term::from_field_text(self.fields.severity, "high")),
            Vulnerabilities::Medium => {
                create_boolean(Occur::Must, Term::from_field_text(self.fields.severity, "medium"))
            }
            Vulnerabilities::Low => create_boolean(Occur::Must, Term::from_field_text(self.fields.severity, "low")),
            Vulnerabilities::Cvss(ordered) => match ordered {
                PartialOrdered::Less(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cvss,
                    Bound::Unbounded,
                    Bound::Excluded(*e),
                )),
                PartialOrdered::LessEqual(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cvss,
                    Bound::Unbounded,
                    Bound::Included(*e),
                )),
                PartialOrdered::Greater(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cvss,
                    Bound::Excluded(*e),
                    Bound::Unbounded,
                )),
                PartialOrdered::GreaterEqual(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cvss,
                    Bound::Included(*e),
                    Bound::Unbounded,
                )),
                PartialOrdered::Range(from, to) => Box::new(RangeQuery::new_f64_bounds(self.fields.cvss, *from, *to)),
            },
            Vulnerabilities::Initial(ordered) => Self::create_date_query(self.fields.advisory_initial, ordered),
            Vulnerabilities::Release(ordered) => {
                let q1 = Self::create_date_query(self.fields.advisory_current, ordered);
                let q2 = Self::create_date_query(self.fields.cve_release, ordered);
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }
            Vulnerabilities::Discovery(ordered) => Self::create_date_query(self.fields.cve_discovery, ordered),
        }
    }

    fn create_date_query(field: Field, value: &Ordered<time::OffsetDateTime>) -> Box<dyn Query> {
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

fn bound_map<F: FnOnce(T) -> R, T, R>(bound: Bound<T>, func: F) -> Bound<R> {
    match bound {
        Bound::Included(f) => Bound::Included(func(f)),
        Bound::Excluded(f) => Bound::Excluded(func(f)),
        Bound::Unbounded => Bound::Unbounded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trustification_index::IndexStore;

    fn assert_free_form<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        let _ = env_logger::try_init();

        let data = std::fs::read_to_string("../testdata/rhsa-2023_1441.json").unwrap();
        let csaf: Csaf = serde_json::from_str(&data).unwrap();
        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();
        let mut writer = store.indexer().unwrap();
        writer.index(store.index(), &csaf).unwrap();
        writer.commit().unwrap();
        f(store);
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

    #[tokio::test]
    async fn test_free_form_ranges() {
        assert_free_form(|index| {
            let result = index.search("cvss:>5", 0, 100).unwrap();
            assert_eq!(result.len(), 1);

            let result = index.search("cvss:<5", 0, 100).unwrap();
            assert_eq!(result.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_free_form_dates() {
        assert_free_form(|index| {
            let result = index.search("initial:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.len(), 1);

            let result = index.search("discovery:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.len(), 1);

            let result = index.search("release:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.len(), 1);

            let result = index.search("release:>2023-02-08", 0, 100).unwrap();
            assert_eq!(result.len(), 1);

            let result = index.search("release:2022-01-01..2023-01-01", 0, 100).unwrap();
            assert_eq!(result.len(), 0);

            let result = index.search("release:2022-01-01..2024-01-01", 0, 100).unwrap();
            assert_eq!(result.len(), 1);
        });
    }
}
