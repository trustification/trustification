use std::{
    collections::{hash_map::Entry, HashMap},
    ops::Bound,
    time::Duration,
};

use csaf::{
    definitions::{NoteCategory, ProductIdT},
    product_tree::ProductTree,
    Csaf,
};
use log::{debug, warn};
use serde_json::{Map, Value};
use sikula::{mir::Direction, prelude::*};
use tantivy::{
    collector::TopDocs,
    query::{AllQuery, TermSetQuery},
    schema::NumericOptions,
    store::ZstdCompressor,
    DocAddress, DocId, IndexSettings, Score, Searcher, SegmentReader, SnippetGenerator,
};
use time::OffsetDateTime;
use trustification_api::search::SearchOptions;
use trustification_index::{
    boost, create_date_query, create_string_query, create_text_query, field2date, field2float, field2str, field2strvec,
    tantivy::{
        doc,
        query::{BooleanQuery, Query, RangeQuery},
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
    advisory_current_inverse: Field,

    advisory_severity_score: Field,
    advisory_severity_score_inverse: Field,

    cve_severity_count: Field,

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
    cve_cvss_max: Field,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct ProductPackage {
    cpe: Option<String>,
    purl: Option<String>,
}

#[derive(Debug)]
pub struct VexQuery {
    query: Box<dyn Query>,
    sort_by: Option<Field>,
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchHit;
    type Document = Csaf;
    type QueryContext = VexQuery;

    fn settings(&self) -> IndexSettings {
        IndexSettings {
            docstore_compression: tantivy::store::Compressor::Zstd(ZstdCompressor::default()),
            ..Default::default()
        }
    }

    fn index_doc(&self, id: &str, csaf: &Csaf) -> Result<Vec<Document>, SearchError> {
        let document_status = match &csaf.document.tracking.status {
            csaf::document::Status::Draft => "draft",
            csaf::document::Status::Interim => "interim",
            csaf::document::Status::Final => "final",
        };

        let mut document = doc!(
            self.fields.advisory_id => id,
            self.fields.advisory_status => document_status,
            self.fields.advisory_title => csaf.document.title.clone(),
        );

        if let Some(notes) = &csaf.document.notes {
            for note in notes {
                match &note.category {
                    NoteCategory::Description | NoteCategory::Summary => {
                        document.add_text(self.fields.advisory_description, &note.text);
                    }
                    _ => {}
                }
            }
        }

        if let Some(severity) = &csaf.document.aggregate_severity {
            document.add_text(self.fields.advisory_severity, &severity.text);
            let score = match severity.text.as_ref() {
                "Critical" => 1.0,
                "Important" => 0.75,
                "Moderate" => 0.5,
                "Low" => 0.25,
                _ => 0.25,
            };
            document.add_f64(self.fields.advisory_severity_score, score);
            document.add_f64(self.fields.advisory_severity_score_inverse, -score);
        }

        for revision in &csaf.document.tracking.revision_history {
            document.add_text(self.fields.advisory_revision, &revision.summary);
        }

        document.add_date(
            self.fields.advisory_initial,
            DateTime::from_timestamp_millis(csaf.document.tracking.initial_release_date.timestamp_millis()),
        );

        document.add_date(
            self.fields.advisory_current,
            DateTime::from_timestamp_millis(csaf.document.tracking.current_release_date.timestamp_millis()),
        );

        document.add_date(
            self.fields.advisory_current_inverse,
            DateTime::from_timestamp_millis(-csaf.document.tracking.current_release_date.timestamp_millis()),
        );

        let mut cve_severities: HashMap<&str, usize> = HashMap::new();
        let mut cvss_max: Option<f64> = None;

        if let Some(vulns) = &csaf.vulnerabilities {
            for vuln in vulns {
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

                            match &mut cvss_max {
                                Some(current) => {
                                    if cvss3.score().value() > *current {
                                        *current = cvss3.score().value();
                                    }
                                }
                                None => {
                                    cvss_max.replace(cvss3.score().value());
                                }
                            }

                            document.add_text(self.fields.cve_severity, cvss3.severity().as_str());
                            match cve_severities.entry(cvss3.severity().as_str()) {
                                Entry::Occupied(o) => {
                                    *o.into_mut() += 1;
                                }
                                Entry::Vacant(v) => {
                                    v.insert(1);
                                }
                            };
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
                            let (pp, related_pp) = find_product_package(csaf, product);
                            if let Some(p) = pp {
                                if let Some(cpe) = p.cpe {
                                    document.add_text(self.fields.cve_affected, cpe);
                                }
                                if let Some(purl) = p.purl {
                                    document.add_text(self.fields.cve_affected, purl);
                                }
                            }

                            if let Some(p) = related_pp {
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
                            let (pp, related_pp) = find_product_package(csaf, product);
                            if let Some(p) = pp {
                                if let Some(cpe) = p.cpe {
                                    document.add_text(self.fields.cve_fixed, cpe);
                                }
                                if let Some(purl) = p.purl {
                                    document.add_text(self.fields.cve_fixed, purl);
                                }
                            }

                            if let Some(p) = related_pp {
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
            }

            let mut json_severities: Map<String, Value> = Map::new();
            for (key, value) in cve_severities.iter() {
                json_severities.insert(key.to_string(), Value::Number((*value).into()));
            }
            document.add_json_object(self.fields.cve_severity_count, json_severities);

            if let Some(cvss_max) = cvss_max {
                document.add_f64(self.fields.cve_cvss_max, cvss_max);
            }
            debug!("Adding doc: {:?}", document);
        }
        Ok(vec![document])
    }

    fn doc_id_to_term(&self, id: &str) -> Term {
        self.schema
            .get_field("advisory_id")
            .map(|f| Term::from_field_text(f, id))
            .unwrap()
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn prepare_query(&self, q: &str) -> Result<VexQuery, SearchError> {
        if q.is_empty() {
            return Ok(VexQuery {
                query: Box::new(AllQuery),
                sort_by: None,
            });
        }

        let mut query = Vulnerabilities::parse(q).map_err(|err| SearchError::Parser(err.to_string()))?;

        query.term = query.term.compact();

        debug!("Query: {query:?}");

        let mut sort_by = None;
        if let Some(f) = query.sorting.first() {
            match f.qualifier {
                VulnerabilitiesSortable::Severity => match f.direction {
                    Direction::Descending => {
                        sort_by.replace(self.fields.advisory_severity_score);
                    }
                    Direction::Ascending => {
                        sort_by.replace(self.fields.advisory_severity_score_inverse);
                    }
                },
                VulnerabilitiesSortable::Release => match f.direction {
                    Direction::Descending => {
                        sort_by.replace(self.fields.advisory_current);
                    }
                    Direction::Ascending => {
                        sort_by.replace(self.fields.advisory_current_inverse);
                    }
                },
            }
        }

        let query = term2query(&query.term, &|resource| self.resource2query(resource));

        debug!("Processed query: {:?}", query);
        Ok(VexQuery { query, sort_by })
    }

    fn search(
        &self,
        searcher: &Searcher,
        query: &VexQuery,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<(f32, DocAddress)>, usize), SearchError> {
        if let Some(order_by) = query.sort_by {
            let mut hits = Vec::new();
            let result = searcher.search(
                &query.query,
                &(
                    TopDocs::with_limit(limit)
                        .and_offset(offset)
                        .order_by_fast_field::<tantivy::DateTime>(order_by),
                    tantivy::collector::Count,
                ),
            )?;
            for r in result.0 {
                hits.push((1.0, r.1));
            }
            Ok((hits, result.1))
        } else {
            let severity_field = self.fields.advisory_severity_score;
            let advisory_current_field = self.fields.advisory_current;
            let now = tantivy::DateTime::from_utc(OffsetDateTime::now_utc());
            Ok(searcher.search(
                &query.query,
                &(
                    TopDocs::with_limit(limit)
                        .and_offset(offset)
                        .tweak_score(move |segment_reader: &SegmentReader| {
                            let severity_reader = segment_reader.fast_fields().f64(severity_field);
                            if let Err(e) = &severity_reader {
                                log::warn!("Severity reader error: {:?}", e);
                            }

                            let date_reader = segment_reader.fast_fields().date(advisory_current_field);
                            if let Err(e) = &date_reader {
                                log::warn!("Date reader error: {:?}", e);
                            }

                            move |doc: DocId, original_score: Score| {
                                let mut tweaked = original_score;
                                if let Ok(severity_reader) = &severity_reader {
                                    let score = severity_reader.get_val(doc);
                                    log::trace!("CVSS score impact {} -> {}", tweaked, (score as f32) * tweaked);
                                    tweaked *= score as f32;

                                    // Now look at the date, normalize score between 0 and 1 (baseline 1970)
                                    if let Ok(date_reader) = &date_reader {
                                        let date: tantivy::DateTime = date_reader.get_val(doc);
                                        if date < now {
                                            let mut normalized = 2.0
                                                * (date.into_timestamp_secs() as f64
                                                    / now.into_timestamp_secs() as f64);
                                            // If it's the past month, boost it more.
                                            if now.into_utc() - date.into_utc() < Duration::from_secs(30 * 24 * 3600) {
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
    }

    fn process_hit(
        &self,
        doc_address: DocAddress,
        score: f32,
        searcher: &Searcher,
        query: &VexQuery,
        options: &SearchOptions,
    ) -> Result<Self::MatchedDocument, SearchError> {
        let doc = searcher.doc(doc_address)?;
        let snippet_generator = SnippetGenerator::create(searcher, &query.query, self.fields.advisory_description)?;
        let advisory_snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        let advisory_id = field2str(&doc, self.fields.advisory_id)?;
        let advisory_title = field2str(&doc, self.fields.advisory_title)?;
        let advisory_severity = field2str(&doc, self.fields.advisory_severity)?;
        let advisory_date = field2date(&doc, self.fields.advisory_current)?;
        let advisory_desc = field2str(&doc, self.fields.advisory_description)?;

        let cves = field2strvec(&doc, self.fields.cve_id)?
            .iter()
            .map(|s| s.to_string())
            .collect();

        let cvss_max: Option<f64> = field2float(&doc, self.fields.cve_cvss_max).ok();

        let mut cve_severity_count: HashMap<String, u64> = HashMap::new();
        if let Some(Some(data)) = doc.get_first(self.fields.cve_severity_count).map(|d| d.as_json()) {
            for (key, value) in data.iter() {
                if let Value::Number(value) = value {
                    cve_severity_count.insert(key.clone(), value.as_u64().unwrap_or(0));
                }
            }
        }

        let document = SearchDocument {
            advisory_id: advisory_id.to_string(),
            advisory_title: advisory_title.to_string(),
            advisory_date,
            advisory_snippet,
            advisory_severity: advisory_severity.to_string(),
            advisory_desc: advisory_desc.to_string(),
            cves,
            cvss_max,
            cve_severity_count,
        };

        let explanation: Option<serde_json::Value> = if options.explain {
            match query.query.explain(searcher, doc_address) {
                Ok(explanation) => Some(serde_json::to_value(explanation).ok()).unwrap_or(None),
                Err(e) => {
                    warn!("Error producing explanation for document {:?}: {:?}", doc_address, e);
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

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    // TODO use CONST for field names
    pub fn new() -> Self {
        let mut schema = Schema::builder();
        let advisory_id = schema.add_text_field("advisory_id", STRING | FAST | STORED);
        let advisory_status = schema.add_text_field("advisory_status", STRING);
        let advisory_title = schema.add_text_field("advisory_title", TEXT | STORED);
        let advisory_description = schema.add_text_field("advisory_description", TEXT | STORED);
        let advisory_revision = schema.add_text_field("advisory_revision", STRING | STORED);
        let advisory_severity = schema.add_text_field("advisory_severity", STRING | STORED);
        let advisory_initial = schema.add_date_field("advisory_initial_date", INDEXED);
        let advisory_current = schema.add_date_field("advisory_current_date", INDEXED | FAST | STORED);
        let advisory_current_inverse = schema.add_date_field("advisory_current_date_inverse", FAST);
        let advisory_severity_score = schema.add_f64_field("advisory_severity_score", FAST);
        let advisory_severity_score_inverse = schema.add_f64_field("advisory_severity_score_inverse", FAST);

        let cve_id = schema.add_text_field("cve_id", STRING | FAST | STORED);
        let cve_title = schema.add_text_field("cve_title", TEXT | STORED);
        let cve_description = schema.add_text_field("cve_description", TEXT | STORED);
        let cve_discovery = schema.add_date_field("cve_discovery_date", INDEXED);
        let cve_release = schema.add_date_field("cve_release_date", INDEXED | STORED);
        let cve_severity = schema.add_text_field("cve_severity", STRING | FAST);
        let cve_affected = schema.add_text_field("cve_affected", STORED | STRING);
        let cve_fixed = schema.add_text_field("cve_fixed", STORED | STRING);
        let opts: NumericOptions = (FAST | INDEXED | STORED).into();
        let cve_cvss = schema.add_f64_field("cve_cvss", opts.set_fast(tantivy::schema::Cardinality::MultiValues));
        let cve_cvss_max = schema.add_f64_field("cve_cvss_max", FAST | STORED);
        let cve_cwe = schema.add_text_field("cve_cwe", STRING | STORED);

        let cve_severity_count = schema.add_json_field("cve_severity_count", STORED);

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
                advisory_current_inverse,
                advisory_severity_score,
                advisory_severity_score_inverse,

                cve_id,
                cve_title,
                cve_description,
                cve_discovery,
                cve_release,
                cve_severity,
                cve_affected,
                cve_fixed,
                cve_cvss,
                cve_cvss_max,
                cve_cwe,
                cve_severity_count,
            },
        }
    }

    fn resource2query(&self, resource: &Vulnerabilities) -> Box<dyn Query> {
        const ID_WEIGHT: f32 = 1.5;
        const CVE_ID_WEIGHT: f32 = 1.4;
        const ADV_TITLE_WEIGHT: f32 = 1.3;
        const CVE_TITLE_WEIGHT: f32 = 1.3;
        match resource {
            Vulnerabilities::Id(value) => boost(
                Box::new(TermSetQuery::new(vec![Term::from_field_text(
                    self.fields.advisory_id,
                    value,
                )])),
                ID_WEIGHT,
            ),

            Vulnerabilities::Cve(value) => boost(
                Box::new(TermSetQuery::new(vec![Term::from_field_text(
                    self.fields.cve_id,
                    value,
                )])),
                CVE_ID_WEIGHT,
            ),

            Vulnerabilities::Description(primary) => {
                let q1 = create_text_query(self.fields.advisory_description, primary);
                let q2 = create_text_query(self.fields.cve_description, primary);
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Title(primary) => {
                let q1 = boost(create_text_query(self.fields.advisory_title, primary), ADV_TITLE_WEIGHT);
                let q2 = boost(create_text_query(self.fields.cve_title, primary), CVE_TITLE_WEIGHT);
                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Package(primary) => {
                let q1 = create_rewrite_string_query(self.fields.cve_affected, primary);
                let q2 = create_rewrite_string_query(self.fields.cve_fixed, primary);

                Box::new(BooleanQuery::union(vec![q1, q2]))
            }

            Vulnerabilities::Fixed(primary) => create_rewrite_string_query(self.fields.cve_fixed, primary),

            Vulnerabilities::Affected(primary) => create_rewrite_string_query(self.fields.cve_affected, primary),

            Vulnerabilities::Severity(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.advisory_severity,
                value,
            )])),

            Vulnerabilities::Status(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.advisory_status,
                value,
            )])),

            Vulnerabilities::Final => create_string_query(self.fields.advisory_status, &Primary::Equal("final")),
            Vulnerabilities::Critical => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "critical"),
                Term::from_field_text(self.fields.advisory_severity, "Critical"),
            ])),
            Vulnerabilities::High => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "high"),
                Term::from_field_text(self.fields.advisory_severity, "Important"),
            ])),
            Vulnerabilities::Medium => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "medium"),
                Term::from_field_text(self.fields.advisory_severity, "Moderate"),
            ])),
            Vulnerabilities::Low => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "low"),
                Term::from_field_text(self.fields.advisory_severity, "Low"),
            ])),
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
use trustification_index::metadata::doc2metadata;

fn find_product_identifier<'m, F: Fn(&'m ProductIdentificationHelper) -> Option<R>, R>(
    branches: &'m BranchesT,
    product_id: &'m ProductIdT,
    f: &'m F,
) -> Option<R> {
    for branch in branches.0.iter() {
        if let Some(product) = &branch.product {
            if product.product_id.0 == product_id.0 {
                if let Some(helper) = &product.product_identification_helper {
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

fn find_product_ref<'m>(tree: &'m ProductTree, product_id: &ProductIdT) -> Option<(&'m ProductIdT, &'m ProductIdT)> {
    if let Some(rs) = &tree.relationships {
        for r in rs {
            if r.full_product_name.product_id.0 == product_id.0 {
                return Some((&r.product_reference, &r.relates_to_product_reference));
            }
        }
    }
    None
}

fn find_product_package(csaf: &Csaf, product_id: &ProductIdT) -> (Option<ProductPackage>, Option<ProductPackage>) {
    if let Some(tree) = &csaf.product_tree {
        if let Some((p_ref, p_ref_related)) = find_product_ref(tree, product_id) {
            if let Some(branches) = &tree.branches {
                let pp = find_product_identifier(branches, p_ref, &|helper: &ProductIdentificationHelper| {
                    Some(ProductPackage {
                        purl: helper.purl.as_ref().map(|p| p.to_string()),
                        cpe: helper.cpe.as_ref().map(|p| p.to_string()),
                    })
                });

                let related_pp =
                    find_product_identifier(branches, p_ref_related, &|helper: &ProductIdentificationHelper| {
                        Some(ProductPackage {
                            purl: helper.purl.as_ref().map(|p| p.to_string()),
                            cpe: helper.cpe.as_ref().map(|p| p.to_string()),
                        })
                    });

                return (pp, related_pp);
            }
        }
    }
    (None, None)
}

fn create_rewrite_string_query(field: Field, primary: &Primary<'_>) -> Box<dyn Query> {
    match primary {
        Primary::Equal(value) => {
            let rewrite = rewrite_cpe(value);
            create_string_query(field, &Primary::Equal(&rewrite))
        }
        Primary::Partial(value) => {
            let rewrite = rewrite_cpe(value);
            create_string_query(field, &Primary::Partial(&rewrite))
        }
    }
}

// Attempt to parse CPE and rewrite to correctly formatted CPE
fn rewrite_cpe(value: &str) -> String {
    if value.starts_with("cpe:/") {
        if let Ok(cpe) = cpe::uri::Uri::parse(value) {
            return cpe.to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use trustification_index::IndexStore;

    use super::*;

    fn assert_search<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        let _ = env_logger::try_init();

        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();
        let mut writer = store.writer().unwrap();
        for advisory in &["rhsa-2023_1441", "rhsa-2021_3029", "rhsa-2023_3408"] {
            let data = std::fs::read_to_string(format!("../testdata/{}.json", advisory)).unwrap();
            let csaf: Csaf = serde_json::from_str(&data).unwrap();

            writer
                .add_document(store.index_as_mut(), &csaf.document.tracking.id, &csaf)
                .unwrap();
        }

        writer.commit().unwrap();
        f(store);
    }

    fn search(index: &IndexStore<Index>, query: &str) -> (Vec<SearchHit>, usize) {
        index
            .search(
                query,
                0,
                10000,
                SearchOptions {
                    explain: false,
                    metadata: false,
                },
            )
            .unwrap()
    }

    #[tokio::test]
    async fn test_free_form_simple_primary() {
        assert_search(|index| {
            let result = search(&index, "openssl");
            assert_eq!(result.0.len(), 2);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_2() {
        assert_search(|index| {
            let result = search(&index, "CVE-2023-0286");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_3() {
        assert_search(|index| {
            let result = search(&index, r#""RHSA-2023:1441""#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_primary_scoped() {
        assert_search(|index| {
            let result = search(&index, r#""RHSA-2023:1441" in:id"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_final() {
        assert_search(|index| {
            let result = search(&index, "is:final");
            assert_eq!(result.0.len(), 3);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_high() {
        assert_search(|index| {
            let result = search(&index, "is:high");
            assert_eq!(result.0.len(), 3);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_critical() {
        assert_search(|index| {
            let result = search(&index, "is:critical");
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_free_form_ranges() {
        assert_search(|index| {
            let result = search(&index, "cvss:>5");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "cvss:<5");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_dates() {
        assert_search(|index| {
            let result = search(&index, "initial:>2022-01-01");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "discovery:>2022-01-01");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "release:>2022-01-01");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "release:>2023-02-08");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "release:2022-01-01..2023-01-01");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "release:2022-01-01..2024-01-01");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "release:2023-03-23");
            assert_eq!(result.0.len(), 1);

            let result = search(&index, "release:2023-03-24");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "release:2023-03-22");
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_severity() {
        assert_search(|index| {
            let result = search(&index, "severity:Important");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "is:high");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "is:critical");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "is:medium");
            assert_eq!(result.0.len(), 2);

            let result = search(&index, "is:low");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_packages() {
        assert_search(|index| {
            let result = search(
                &index,
                "affected:\"pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?arch=x86_64&epoch=1\"",
            );
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_products() {
        assert_search(|index| {
            let result = search(&index, "fixed:\"cpe:/o:redhat:rhel_eus:8.6::baseos\"");
            assert_eq!(result.0.len(), 2);
        });
    }

    #[tokio::test]
    async fn test_products_partial() {
        assert_search(|index| {
            let result = search(&index, "\"cpe:/o:redhat:rhel_eus\" in:fixed");
            assert_eq!(result.0.len(), 3);
        });
    }

    #[tokio::test]
    async fn test_delete_document() {
        assert_search(|mut index| {
            // our data is there
            let result = search(&index, r#""RHSA-2023:1441" in:id"#);
            assert_eq!(result.0.len(), 1);

            // Now we remove the entry from the index
            let writer = index.writer().unwrap();
            writer.delete_document(index.index(), "RHSA-2023:1441");
            writer.commit().unwrap();

            // Ta-da ! No more data
            let result = search(&index, r#""RHSA-2023:1441" in:id"#);
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_all() {
        assert_search(|index| {
            let result = search(&index, "");
            // Should get all documents (1)
            assert_eq!(result.0.len(), 3);
        });
    }

    #[tokio::test]
    async fn test_severity_count() {
        assert_search(|index| {
            let result = search(&index, "");
            assert_eq!(result.0.len(), 3);
            assert_eq!(result.0[0].document.cve_severity_count.len(), 3);
            assert_eq!(result.0[0].document.cve_severity_count["high"], 1);
        });
    }

    #[tokio::test]
    async fn test_sorting() {
        assert_search(|index| {
            let result = search(&index, "openssl sort:release");
            assert_eq!(result.0.len(), 2);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2023:1441");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:3408");
            assert!(result.0[0].document.advisory_date < result.0[1].document.advisory_date);

            let result = search(&index, "openssl -sort:release");
            assert_eq!(result.0.len(), 2);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2023:3408");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:1441");
            assert!(result.0[0].document.advisory_date > result.0[1].document.advisory_date);
        });
    }
}
