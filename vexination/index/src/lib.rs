mod search;

use std::ops::Bound;

use csaf::{
    definitions::{NoteCategory, ProductIdT},
    product_tree::ProductTree,
    Csaf,
};
use search::*;
use sikula::prelude::*;
use tantivy::{Searcher, SnippetGenerator};
use tracing::debug;
use trustification_index::{
    create_boolean_query, create_date_query, field2date, field2float, field2str, primary2occur,
    tantivy::{
        doc,
        query::{BooleanQuery, Occur, Query, RangeQuery},
        schema::{Field, Schema, Term, FAST, INDEXED, STORED, STRING, TEXT},
        DateTime,
    },
    term2query, Document, Error as SearchError,
};
use vexination_model::prelude::*;

pub struct Index {
    schema: Schema,
    fields: Fields,
}

struct Fields {
    advisory_id: Field,
    advisory_status: Field,
    advisory_title: Field,
    advisory_description: Field,
    advisory_severity: Field,
    advisory_revision: Field,
    advisory_initial: Field,
    advisory_current: Field,

    cve_id: Field,
    cve_title: Field,
    cve_description: Field,
    cve_release: Field,
    cve_discovery: Field,
    cve_severity: Field,
    cve_cvss: Field,
    cve_fixed: Field,
    cve_affected: Field,
    cve_cwe: Field,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProductPackage {
    cpe: Option<String>,
    purl: Option<String>,
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchDocument;
    type Document = Csaf;

    fn index_doc(&self, id: &str, csaf: &Csaf) -> Result<Vec<Document>, SearchError> {
        let mut documents = Vec::new();
        let document_status = match &csaf.document.tracking.status {
            csaf::document::Status::Draft => "draft",
            csaf::document::Status::Interim => "interim",
            csaf::document::Status::Final => "final",
        };

        let mut base = doc!(
            self.fields.advisory_id => id,
            self.fields.advisory_status => document_status,
            self.fields.advisory_title => csaf.document.title.clone(),
        );

        if let Some(notes) = &csaf.document.notes {
            for note in notes {
                match &note.category {
                    NoteCategory::Description | NoteCategory::Summary => {
                        base.add_text(self.fields.advisory_description, &note.text);
                    }
                    _ => {}
                }
            }
        }

        if let Some(severity) = &csaf.document.aggregate_severity {
            base.add_text(self.fields.advisory_severity, &severity.text);
        }

        for revision in &csaf.document.tracking.revision_history {
            base.add_text(self.fields.advisory_revision, &revision.summary);
        }

        base.add_date(
            self.fields.advisory_initial,
            DateTime::from_timestamp_millis(csaf.document.tracking.initial_release_date.timestamp_millis()),
        );

        base.add_date(
            self.fields.advisory_current,
            DateTime::from_timestamp_millis(csaf.document.tracking.current_release_date.timestamp_millis()),
        );

        if let Some(vulns) = &csaf.vulnerabilities {
            for vuln in vulns {
                let mut document = base.clone();
                if let Some(title) = &vuln.title {
                    document.add_text(self.fields.cve_title, title);
                }

                if let Some(cve) = &vuln.cve {
                    document.add_text(self.fields.cve_id, cve);
                }

                if let Some(scores) = &vuln.scores {
                    for score in scores {
                        if let Some(cvss3) = &score.cvss_v3 {
                            document.add_f64(self.fields.cve_cvss, cvss3.score().value());
                            document.add_text(self.fields.cve_severity, cvss3.severity().as_str());
                        }
                    }
                }

                if let Some(cwe) = &vuln.cwe {
                    document.add_text(self.fields.cve_cwe, &cwe.id);
                }

                if let Some(notes) = &vuln.notes {
                    for note in notes {
                        if let NoteCategory::Description = note.category {
                            document.add_text(self.fields.cve_description, note.text.as_str());
                        }
                    }
                }

                if let Some(status) = &vuln.product_status {
                    if let Some(products) = &status.known_affected {
                        for product in products {
                            if let Some(p) = find_product_package(csaf, product) {
                                if let Some(cpe) = p.cpe {
                                    document.add_text(self.fields.cve_affected, cpe);
                                }
                                if let Some(purl) = p.purl {
                                    document.add_text(self.fields.cve_affected, purl);
                                }
                            }
                        }
                    }

                    if let Some(products) = &status.fixed {
                        for product in products {
                            if let Some(p) = find_product_package(csaf, product) {
                                if let Some(cpe) = p.cpe {
                                    document.add_text(self.fields.cve_fixed, cpe);
                                }
                                if let Some(purl) = p.purl {
                                    document.add_text(self.fields.cve_fixed, purl);
                                }
                            }
                        }
                    }
                }

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

                debug!("Adding doc: {:?}", document);
                documents.push(document);
            }
        }
        Ok(documents)
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, SearchError> {
        let mut query = Vulnerabilities::parse(q).map_err(|err| SearchError::Parser(err.to_string()))?;

        query.term = query.term.compact();

        debug!("Query: {query:?}");

        let query = term2query(&query.term, &|resource| self.resource2query(resource));

        debug!("Processed query: {:?}", query);
        Ok(query)
    }

    fn process_hit(
        &self,
        doc: Document,
        searcher: &Searcher,
        query: &dyn Query,
    ) -> Result<Self::MatchedDocument, SearchError> {
        let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.advisory_description)?;
        let advisory_snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        let advisory_id = field2str(&doc, self.fields.advisory_id)?;
        let advisory_title = field2str(&doc, self.fields.advisory_title)?;
        let advisory_date = field2date(&doc, self.fields.advisory_current)?;
        let advisory_desc = field2str(&doc, self.fields.advisory_description)?;

        let cve_id = field2str(&doc, self.fields.cve_id)?;
        let cve_title = field2str(&doc, self.fields.cve_title)?;
        let cve_release = field2date(&doc, self.fields.cve_release)?;
        let cve_cvss = field2float(&doc, self.fields.cve_cvss).ok();
        let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.cve_description)?;
        let cve_desc = field2str(&doc, self.fields.cve_description)?;
        let cve_snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        Ok(SearchDocument {
            advisory_id: advisory_id.to_string(),
            advisory_title: advisory_title.to_string(),
            advisory_date,
            advisory_snippet,
            advisory_desc: advisory_desc.to_string(),
            cve_id: cve_id.to_string(),
            cve_title: cve_title.to_string(),
            cve_release,
            cve_snippet,
            cve_desc: cve_desc.to_string(),
            cve_cvss,
        })
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    pub fn new() -> Self {
        let mut schema = Schema::builder();
        let advisory_id = schema.add_text_field("advisory_id", STRING | FAST | STORED);
        let advisory_status = schema.add_text_field("advisory_status", STRING);
        let advisory_title = schema.add_text_field("advisory_title", TEXT | STORED);
        let advisory_description = schema.add_text_field("advisory_description", TEXT | STORED);
        let advisory_revision = schema.add_text_field("advisory_revision", STRING | STORED);
        let advisory_severity = schema.add_text_field("advisory_severity", STRING | STORED);
        let advisory_initial = schema.add_date_field("advisory_initial_date", INDEXED);
        let advisory_current = schema.add_date_field("advisory_current_date", INDEXED | STORED);

        let cve_id = schema.add_text_field("cve_id", STRING | FAST | STORED);
        let cve_title = schema.add_text_field("cve_title", TEXT | STORED);
        let cve_description = schema.add_text_field("cve_description", TEXT | STORED);
        let cve_discovery = schema.add_date_field("cve_discovery_date", INDEXED);
        let cve_release = schema.add_date_field("cve_release_date", INDEXED | STORED);
        let cve_severity = schema.add_text_field("cve_severity", STRING | FAST);
        let cve_affected = schema.add_text_field("cve_affected", STORED | STRING);
        let cve_fixed = schema.add_text_field("cve_fixed", STORED | STRING);
        let cve_cvss = schema.add_f64_field("cve_cvss", FAST | INDEXED | STORED);
        let cve_cwe = schema.add_text_field("cve_cwe", STRING | STORED);

        Self {
            schema: schema.build(),
            fields: Fields {
                advisory_id,
                advisory_status,
                advisory_title,
                advisory_description,
                advisory_revision,
                advisory_severity,
                advisory_initial,
                advisory_current,

                cve_id,
                cve_title,
                cve_description,
                cve_discovery,
                cve_release,
                cve_severity,
                cve_affected,
                cve_fixed,
                cve_cvss,
                cve_cwe,
            },
        }
    }

    fn resource2query(&self, resource: &Vulnerabilities) -> Box<dyn Query> {
        match resource {
            Vulnerabilities::Id(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.advisory_id, value);
                create_boolean_query(occur, term)
            }

            Vulnerabilities::Cve(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve_id, value);
                create_boolean_query(occur, term)
            }

            Vulnerabilities::Description(primary) => {
                let (occur, value) = primary2occur(primary);
                let q1 = create_boolean_query(occur, Term::from_field_text(self.fields.advisory_description, value));
                let q2 = create_boolean_query(occur, Term::from_field_text(self.fields.cve_description, value));
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Title(primary) => {
                let (occur, value) = primary2occur(primary);
                let q1 = create_boolean_query(occur, Term::from_field_text(self.fields.advisory_title, value));
                let q2 = create_boolean_query(occur, Term::from_field_text(self.fields.cve_title, value));
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Package(primary) => {
                let (occur, value) = primary2occur(primary);
                let q1 = create_boolean_query(occur, Term::from_field_text(self.fields.cve_affected, value));
                let q2 = create_boolean_query(occur, Term::from_field_text(self.fields.cve_fixed, value));

                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Fixed(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve_fixed, value);
                create_boolean_query(occur, term)
            }

            Vulnerabilities::Affected(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve_affected, value);
                create_boolean_query(occur, term)
            }

            Vulnerabilities::Severity(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.cve_severity, value);
                create_boolean_query(occur, term)
            }

            Vulnerabilities::Status(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.advisory_status, value);
                create_boolean_query(occur, term)
            }
            Vulnerabilities::Final => {
                create_boolean_query(Occur::Must, Term::from_field_text(self.fields.advisory_status, "final"))
            }
            Vulnerabilities::Critical => {
                create_boolean_query(Occur::Must, Term::from_field_text(self.fields.cve_severity, "critical"))
            }
            Vulnerabilities::High => {
                create_boolean_query(Occur::Must, Term::from_field_text(self.fields.cve_severity, "high"))
            }
            Vulnerabilities::Medium => {
                create_boolean_query(Occur::Must, Term::from_field_text(self.fields.cve_severity, "medium"))
            }
            Vulnerabilities::Low => {
                create_boolean_query(Occur::Must, Term::from_field_text(self.fields.cve_severity, "low"))
            }
            Vulnerabilities::Cvss(ordered) => match ordered {
                PartialOrdered::Less(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cve_cvss,
                    Bound::Unbounded,
                    Bound::Excluded(*e),
                )),
                PartialOrdered::LessEqual(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cve_cvss,
                    Bound::Unbounded,
                    Bound::Included(*e),
                )),
                PartialOrdered::Greater(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cve_cvss,
                    Bound::Excluded(*e),
                    Bound::Unbounded,
                )),
                PartialOrdered::GreaterEqual(e) => Box::new(RangeQuery::new_f64_bounds(
                    self.fields.cve_cvss,
                    Bound::Included(*e),
                    Bound::Unbounded,
                )),
                PartialOrdered::Range(from, to) => {
                    Box::new(RangeQuery::new_f64_bounds(self.fields.cve_cvss, *from, *to))
                }
            },
            Vulnerabilities::Initial(ordered) => create_date_query(self.fields.advisory_initial, ordered),
            Vulnerabilities::Release(ordered) => {
                let q1 = create_date_query(self.fields.advisory_current, ordered);
                let q2 = create_date_query(self.fields.cve_release, ordered);
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }
            Vulnerabilities::Discovery(ordered) => create_date_query(self.fields.cve_discovery, ordered),
        }
    }
}

use csaf::definitions::{BranchesT, ProductIdentificationHelper};
fn find_product_identifier<'m, F: Fn(&'m ProductIdentificationHelper) -> Option<R>, R>(
    branches: &'m BranchesT,
    product_id: &'m ProductIdT,
    f: &'m F,
) -> Option<R> {
    for branch in branches.0.iter() {
        if branch.name == product_id.0 {
            if let Some(name) = &branch.product {
                if let Some(helper) = &name.product_identification_helper {
                    if let Some(ret) = f(helper) {
                        return Some(ret);
                    }
                }
            }
        }

        if let Some(branches) = &branch.branches {
            if let Some(ret) = find_product_identifier(branches, product_id, f) {
                return Some(ret);
            }
        }
    }
    None
}

fn find_product_ref<'m>(tree: &'m ProductTree, product_id: &ProductIdT) -> Option<&'m ProductIdT> {
    if let Some(rs) = &tree.relationships {
        for r in rs {
            if r.full_product_name.product_id.0 == product_id.0 {
                return Some(&r.product_reference);
            }
        }
    }
    None
}

fn find_product_package(csaf: &Csaf, product_id: &ProductIdT) -> Option<ProductPackage> {
    if let Some(tree) = &csaf.product_tree {
        if let Some(r) = find_product_ref(tree, product_id) {
            if let Some(branches) = &tree.branches {
                return find_product_identifier(branches, r, &|helper: &ProductIdentificationHelper| {
                    Some(ProductPackage {
                        purl: helper.purl.as_ref().map(|p| p.to_string()),
                        cpe: helper.cpe.as_ref().map(|p| p.to_string()),
                    })
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use trustification_index::IndexStore;

    use super::*;

    fn assert_free_form<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        let _ = env_logger::try_init();

        let data = std::fs::read_to_string("../testdata/rhsa-2023_1441.json").unwrap();
        let csaf: Csaf = serde_json::from_str(&data).unwrap();
        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();
        let mut writer = store.writer().unwrap();
        writer.write(store.index(), &csaf.document.tracking.id, &csaf).unwrap();
        writer.commit().unwrap();
        f(store);
    }

    #[tokio::test]
    async fn test_free_form_simple_primary() {
        assert_free_form(|index| {
            let result = index.search("openssl", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_2() {
        assert_free_form(|index| {
            let result = index.search("CVE-2023-0286", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_3() {
        assert_free_form(|index| {
            let result = index.search("RHSA-2023:1441", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_primary_scoped() {
        assert_free_form(|index| {
            let result = index.search("RHSA-2023:1441 in:id", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_final() {
        assert_free_form(|index| {
            let result = index.search("is:final", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_high() {
        assert_free_form(|index| {
            let result = index.search("is:high", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_critical() {
        assert_free_form(|index| {
            let result = index.search("is:critical", 0, 100).unwrap();
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_free_form_ranges() {
        assert_free_form(|index| {
            let result = index.search("cvss:>5", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("cvss:<5", 0, 100).unwrap();
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_free_form_dates() {
        assert_free_form(|index| {
            let result = index.search("initial:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("discovery:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("release:>2022-01-01", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("release:>2023-02-08", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);

            let result = index.search("release:2022-01-01..2023-01-01", 0, 100).unwrap();
            assert_eq!(result.0.len(), 0);

            let result = index.search("release:2022-01-01..2024-01-01", 0, 100).unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_packages() {
        assert_free_form(|index| {
            let result = index
                .search(
                    "affected:\"pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?arch=x86_64&epoch=1\"",
                    0,
                    100,
                )
                .unwrap();
            assert_eq!(result.0.len(), 1);
        });
    }
}
