use csaf::{
    definitions::{BranchesT, NoteCategory, ProductIdT, ProductIdentificationHelper},
    product_tree::ProductTree,
    Csaf,
};
use log::{debug, warn};
use serde_json::{Map, Value};
use sikula::prelude::*;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    time::Duration,
};
use time::OffsetDateTime;
use trustification_api::search::SearchOptions;
use trustification_index::{
    boost, create_date_query, create_float_query, create_string_query, create_string_query_case, create_text_query,
    field2date, field2float, field2str, field2str_opt, field2strvec,
    metadata::doc2metadata,
    sort_by,
    tantivy::{
        self,
        collector::TopDocs,
        doc,
        query::{AllQuery, BooleanQuery, Query, TermSetQuery},
        schema::{Field, Schema, Term, FAST, INDEXED, STORED, STRING, TEXT},
        store::ZstdCompressor,
        DateTime, DocAddress, DocId, IndexSettings, Score, Searcher, SegmentReader, SnippetGenerator,
    },
    term2query, Case, Document, Error as SearchError, SearchQuery,
};
use vexination_model::prelude::*;

pub struct Index {
    schema: Schema,
    fields: Fields,
}

struct Fields {
    indexed_timestamp: Field,

    /// the ID of the advisory, converted to uppercase for case-insensitive search
    advisory_id: Field,
    /// the original ID of the advisory, as stored in the document
    advisory_id_raw: Field,

    advisory_status: Field,
    advisory_title: Field,
    advisory_description: Field,
    advisory_severity: Field,
    advisory_revision: Field,
    advisory_initial: Field,
    advisory_current: Field,

    advisory_severity_score: Field,

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
    cve_not_affected: Field,
    cve_cwe: Field,
    cve_cvss_max: Field,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct ProductPackage {
    cpe: Option<String>,
    purl: Option<String>,
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchHit;

    fn prepare_query(&self, q: &str) -> Result<SearchQuery, SearchError> {
        let mut query = Vulnerabilities::parse(q).map_err(|err| SearchError::QueryParser(err.to_string()))?;

        query.term = query.term.compact();

        debug!("Query: {query:?}");

        let sort_by = query.sorting.first().map(|f| match f.qualifier {
            VulnerabilitiesSortable::Severity => sort_by(f.direction, self.fields.advisory_severity_score),
            VulnerabilitiesSortable::Release => sort_by(f.direction, self.fields.advisory_current),
            VulnerabilitiesSortable::IndexedTimestamp => sort_by(f.direction, self.fields.indexed_timestamp),
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
        let severity_field = self
            .schema
            .get_field_name(self.fields.advisory_severity_score)
            .to_string();
        let date_field = self.schema.get_field_name(self.fields.advisory_current).to_string();
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
        let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.advisory_description)?;
        let advisory_snippet = snippet_generator.snippet_from_doc(&doc).to_html();

        let advisory_id = field2str(&self.schema, &doc, self.fields.advisory_id_raw)?;

        let advisory_title = field2str(&self.schema, &doc, self.fields.advisory_title)?;
        let advisory_severity = field2str_opt(&doc, self.fields.advisory_severity);
        let advisory_date = field2date(&self.schema, &doc, self.fields.advisory_current)?;
        let advisory_desc = field2str(&self.schema, &doc, self.fields.advisory_description).unwrap_or("");

        let cves = field2strvec(&doc, self.fields.cve_id)?
            .iter()
            .map(|s| s.to_string())
            .collect();

        let cvss_max: Option<f64> = field2float(&self.schema, &doc, self.fields.cve_cvss_max).ok();

        let mut cve_severity_count: HashMap<String, u64> = HashMap::new();
        if let Some(Some(data)) = doc.get_first(self.fields.cve_severity_count).map(|d| d.as_json()) {
            for (key, value) in data.iter() {
                if let Value::Number(value) = value {
                    cve_severity_count.insert(key.clone(), value.as_u64().unwrap_or(0));
                }
            }
        }

        let indexed_timestamp = doc
            .get_first(self.fields.indexed_timestamp)
            .map(|s| {
                s.as_date()
                    .map(|d| d.into_utc())
                    .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            })
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        let document = SearchDocument {
            advisory_id: advisory_id.to_string(),
            advisory_title: advisory_title.to_string(),
            advisory_date,
            advisory_snippet,
            advisory_severity: advisory_severity.map(ToString::to_string),
            advisory_desc: advisory_desc.to_string(),
            cves,
            cvss_max,
            cve_severity_count,
            indexed_timestamp,
        };

        let explanation = if options.explain {
            match query.explain(searcher, doc_address) {
                Ok(explanation) => serde_json::to_value(explanation).ok(),
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

impl trustification_index::WriteIndex for Index {
    type Document = Csaf;

    fn name(&self) -> &str {
        "vex"
    }

    fn settings(&self) -> IndexSettings {
        IndexSettings {
            docstore_compression: tantivy::store::Compressor::Zstd(ZstdCompressor::default()),
            ..Default::default()
        }
    }

    fn parse_doc(&self, data: &[u8]) -> Result<Csaf, SearchError> {
        serde_json::from_slice::<Csaf>(data).map_err(|e| SearchError::DocParser(e.to_string()))
    }

    fn index_doc(&self, id: &str, csaf: &Csaf) -> Result<Vec<(String, Document)>, SearchError> {
        let document_status = match &csaf.document.tracking.status {
            csaf::document::Status::Draft => "draft",
            csaf::document::Status::Interim => "interim",
            csaf::document::Status::Final => "final",
        };

        let mut documents: Vec<(String, Document)> = Vec::new();

        let mut document = doc!(
            self.fields.advisory_id => id.to_uppercase(),
            self.fields.advisory_id_raw => id,
            self.fields.advisory_status => document_status,
            self.fields.advisory_title => csaf.document.title.clone(),
        );

        document.add_date(
            self.fields.indexed_timestamp,
            DateTime::from_utc(OffsetDateTime::now_utc()),
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
            let severity = severity.text.to_lowercase();
            document.add_text(self.fields.advisory_severity, &severity);
            let score = match severity.as_ref() {
                "critical" => 1.0,
                "important" => 0.75,
                "moderate" => 0.5,
                "low" => 0.25,
                _ => 0.25,
            };
            document.add_f64(self.fields.advisory_severity_score, score);
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

        let mut cve_severities: HashMap<&str, usize> = HashMap::new();
        let mut cvss_max: Option<f64> = None;
        let mut fixed: HashSet<String> = HashSet::new();
        let mut affected: HashSet<String> = HashSet::new();
        let mut no_affected: HashSet<String> = HashSet::new();

        if let Some(vulns) = &csaf.vulnerabilities {
            for vuln in vulns {
                if let Some(title) = &vuln.title {
                    document.add_text(self.fields.cve_title, title);
                }

                if let Some(cve) = &vuln.cve {
                    document.add_text(self.fields.cve_id, cve.to_uppercase());
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
                                    affected.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    affected.insert(purl);
                                }
                            }

                            if let Some(p) = related_pp {
                                if let Some(cpe) = p.cpe {
                                    affected.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    affected.insert(purl);
                                }
                            }
                        }
                    }

                    if let Some(products) = &status.fixed {
                        for product in products {
                            let (pp, related_pp) = find_product_package(csaf, product);
                            if let Some(p) = pp {
                                if let Some(cpe) = p.cpe {
                                    fixed.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    fixed.insert(purl);
                                }
                            }

                            if let Some(p) = related_pp {
                                if let Some(cpe) = p.cpe {
                                    fixed.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    fixed.insert(purl);
                                }
                            }
                        }
                    }

                    if let Some(products) = &status.known_not_affected {
                        for product in products {
                            let (pp, related_pp) = find_product_package(csaf, product);
                            if let Some(p) = pp {
                                if let Some(cpe) = p.cpe {
                                    no_affected.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    no_affected.insert(purl);
                                }
                            }

                            if let Some(p) = related_pp {
                                if let Some(cpe) = p.cpe {
                                    no_affected.insert(cpe);
                                }
                                if let Some(purl) = p.purl {
                                    no_affected.insert(purl);
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

            for affected in affected {
                document.add_text(self.fields.cve_affected, affected);
            }

            for fixed in fixed {
                document.add_text(self.fields.cve_fixed, fixed);
            }

            for no_affected in no_affected {
                document.add_text(self.fields.cve_not_affected, no_affected);
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
        documents.push((id.to_string(), document));
        Ok(documents)
    }

    fn doc_id_to_term(&self, id: &str) -> Term {
        self.schema
            .get_field("advisory_id_raw")
            .map(|f| Term::from_field_text(f, id))
            .expect("the document schema defines this field")
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
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
        let indexed_timestamp = schema.add_date_field("indexed_timestamp", INDEXED | FAST | STORED);

        let advisory_id = schema.add_text_field("advisory_id", STRING | FAST);
        let advisory_id_raw = schema.add_text_field("advisory_id_raw", STRING | STORED);
        let advisory_status = schema.add_text_field("advisory_status", STRING);
        let advisory_title = schema.add_text_field("advisory_title", TEXT | STORED);
        let advisory_description = schema.add_text_field("advisory_description", TEXT | STORED);
        let advisory_revision = schema.add_text_field("advisory_revision", STRING | STORED);
        let advisory_severity = schema.add_text_field("advisory_severity", STRING | STORED);
        let advisory_initial = schema.add_date_field("advisory_initial_date", INDEXED);
        let advisory_current = schema.add_date_field("advisory_current_date", INDEXED | FAST | STORED);
        let advisory_severity_score = schema.add_f64_field("advisory_severity_score", FAST);

        let cve_id = schema.add_text_field("cve_id", STRING | FAST | STORED);
        let cve_title = schema.add_text_field("cve_title", TEXT | STORED);
        let cve_description = schema.add_text_field("cve_description", TEXT | STORED);
        let cve_discovery = schema.add_date_field("cve_discovery_date", INDEXED);
        let cve_release = schema.add_date_field("cve_release_date", INDEXED | STORED);
        let cve_severity = schema.add_text_field("cve_severity", STRING | FAST);
        let cve_affected = schema.add_text_field("cve_affected", STORED | STRING);
        let cve_not_affected = schema.add_text_field("cve_not_affected", STORED | STRING);
        let cve_fixed = schema.add_text_field("cve_fixed", STORED | STRING);
        let cve_cvss = schema.add_f64_field("cve_cvss", FAST | INDEXED | STORED);
        let cve_cvss_max = schema.add_f64_field("cve_cvss_max", FAST | STORED);
        let cve_cwe = schema.add_text_field("cve_cwe", STRING | STORED);

        let cve_severity_count = schema.add_json_field("cve_severity_count", STORED);

        Self {
            schema: schema.build(),
            fields: Fields {
                indexed_timestamp,

                advisory_id,
                advisory_id_raw,
                advisory_status,
                advisory_title,
                advisory_description,
                advisory_revision,
                advisory_severity,
                advisory_initial,
                advisory_current,
                advisory_severity_score,

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
                cve_not_affected,
            },
        }
    }

    fn resource2query(&self, resource: &Vulnerabilities) -> Box<dyn Query> {
        const ID_WEIGHT: f32 = 1.5;
        const CVE_ID_WEIGHT: f32 = 1.4;
        const ADV_TITLE_WEIGHT: f32 = 1.3;
        const CVE_TITLE_WEIGHT: f32 = 1.3;
        match resource {
            Vulnerabilities::Id(primary) => boost(
                create_string_query_case(self.fields.advisory_id, primary, Case::Uppercase),
                ID_WEIGHT,
            ),
            Vulnerabilities::Cve(primary) => boost(
                create_string_query_case(self.fields.cve_id, primary, Case::Uppercase),
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
                let q3 = create_rewrite_string_query(self.fields.cve_not_affected, primary);

                Box::new(BooleanQuery::union(vec![q1, q2, q3]))
            }

            Vulnerabilities::Fixed(primary) => create_rewrite_string_query(self.fields.cve_fixed, primary),

            Vulnerabilities::Affected(primary) => create_rewrite_string_query(self.fields.cve_affected, primary),

            Vulnerabilities::NotAffected(primary) => create_rewrite_string_query(self.fields.cve_not_affected, primary),

            Vulnerabilities::Severity(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.advisory_severity,
                &value.to_ascii_lowercase(),
            )])),

            Vulnerabilities::Status(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.advisory_status,
                value,
            )])),

            Vulnerabilities::Final => create_string_query(self.fields.advisory_status, &Primary::Equal("final")),
            Vulnerabilities::Critical => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "critical"),
                Term::from_field_text(self.fields.advisory_severity, "critical"),
            ])),
            Vulnerabilities::High => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "high"),
                Term::from_field_text(self.fields.advisory_severity, "important"),
            ])),
            Vulnerabilities::Medium => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "medium"),
                Term::from_field_text(self.fields.advisory_severity, "moderate"),
            ])),
            Vulnerabilities::Low => Box::new(TermSetQuery::new(vec![
                Term::from_field_text(self.fields.cve_severity, "low"),
                Term::from_field_text(self.fields.advisory_severity, "low"),
            ])),
            Vulnerabilities::Cvss(ordered) => create_float_query(&self.schema, [self.fields.cve_cvss], ordered),
            Vulnerabilities::Initial(ordered) => create_date_query(&self.schema, self.fields.advisory_initial, ordered),
            Vulnerabilities::Release(ordered) => create_date_query(&self.schema, self.fields.advisory_current, ordered),
            Vulnerabilities::CveRelease(ordered) => create_date_query(&self.schema, self.fields.cve_release, ordered),
            Vulnerabilities::CveDiscovery(ordered) => {
                create_date_query(&self.schema, self.fields.cve_discovery, ordered)
            }
            Vulnerabilities::IndexedTimestamp(value) => {
                create_date_query(&self.schema, self.fields.indexed_timestamp, value)
            }
        }
    }
}

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
            let rewrite = rewrite_cpe_partial(value);
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

// Attempt to parse CPE and rewrite to partial match-friendly string
fn rewrite_cpe_partial(value: &str) -> String {
    if value.starts_with("cpe:/") {
        if let Ok(cpe) = cpe::uri::Uri::parse(value) {
            return cpe.to_string().trim_end_matches(|x| x == ':' || x == '*').to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use time::format_description;
    use trustification_index::IndexStore;

    use super::*;

    fn assert_search<F>(f: F)
    where
        F: FnOnce(IndexStore<Index>),
    {
        assert_search_with(
            ["rhsa-2023_1441", "rhsa-2021_3029", "rhsa-2023_3408", "rhsa-2023_4378"],
            f,
        )
    }

    fn assert_search_with<F, I, S>(advisories: I, f: F)
    where
        F: FnOnce(IndexStore<Index>),
        I: IntoIterator<Item = S>,
        S: Display,
    {
        let _ = env_logger::try_init();

        let index = Index::new();
        let mut store = IndexStore::new_in_memory(index).unwrap();

        let mut writer = store.writer().unwrap();
        for advisory in advisories {
            let data = std::fs::read_to_string(format!("../testdata/{}.json", advisory)).unwrap();
            let csaf: Csaf = serde_json::from_str(&data).unwrap();

            writer
                .add_document(store.index_as_mut(), &csaf.document.tracking.id, data.as_bytes())
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
                    explain: true,
                    ..Default::default()
                },
            )
            .unwrap()
    }

    #[tokio::test]
    async fn test_lowercase_id() {
        assert_search_with(["lowercase-id"], |index| {
            let result = search(&index, "security");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_lowercase_id_reupload() {
        assert_search_with(["lowercase-id", "lowercase-id"], |index| {
            let result = search(&index, "security");
            assert_eq!(result.0.len(), 1);
        });
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
    async fn test_free_form_simple_primary_lowercase_2() {
        assert_search(|index| {
            let result = search(&index, "cve-2023-0286");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_free_form_simple_primary_lowercase_partial() {
        assert_search(|index| {
            let result = search(&index, "cve-2023-028");
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
            assert_eq!(result.0.len(), 4);
        });
    }

    #[tokio::test]
    async fn test_free_form_predicate_high() {
        assert_search(|index| {
            let result = search(&index, "is:high");
            assert_eq!(result.0.len(), 4);
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
            assert_eq!(result.0.len(), 4);

            let result = search(&index, "cvss:<5");
            assert_eq!(result.0.len(), 2);
        });
    }

    #[tokio::test]
    async fn test_free_form_dates() {
        assert_search(|index| {
            let result = search(&index, "initial:>2022-01-01");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "cveDiscovery:>2022-01-01");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "release:>2022-01-01");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "release:>2023-02-08");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "release:2022-01-01..2023-01-01");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "release:2022-01-01..2024-01-01");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "release:2023-03-23");
            assert_eq!(result.0.len(), 1);

            let result = search(&index, "release:2023-03-24");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "release:2023-03-22");
            assert_eq!(result.0.len(), 0);
        });
    }

    #[tokio::test]
    async fn test_title_case_insensitive() {
        assert_search(|index| {
            let result = search(&index, r#""microcode" in:title"#);
            assert_eq!(result.0.len(), 1);
        });
        assert_search(|index| {
            let result = search(&index, r#""Microcode" in:title"#);
            assert_eq!(result.0.len(), 1);
        });
        assert_search(|index| {
            let result = search(&index, r#""MICROCODE" in:title"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    /// Test if we can find a word containing special characters in title or description
    #[tokio::test]
    #[ignore]
    async fn test_title_special() {
        assert_search(|index| {
            let result = search(&index, r#"microcode_ctl in:title"#);
            assert_eq!(result.0.len(), 1);
        });
        assert_search(|index| {
            let result = search(&index, r#"Microcode_Ctl in:title"#);
            assert_eq!(result.0.len(), 1);
        });
        assert_search(|index| {
            let result = search(&index, r#"MICROCODE_CTL in:title"#);
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_severity() {
        assert_search(|index| {
            let result = search(&index, "severity:Important");
            assert_eq!(result.0.len(), 3);

            let result = search(&index, "is:high");
            assert_eq!(result.0.len(), 4);

            let result = search(&index, "is:critical");
            assert_eq!(result.0.len(), 0);

            let result = search(&index, "is:medium");
            assert_eq!(result.0.len(), 3);

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

    // Unit test for issue #436 (https://github.com/trustification/trustification/issues/436)
    #[tokio::test]
    async fn test_query_and_products() {
        assert_search(|index| {
            let result = search(&index, "kernel");
            assert_eq!(result.0.len(), 1);

            let result = search(&index, "\"cpe:/a:redhat:enterprise_linux:9\" in:package");
            assert_eq!(result.0.len(), 1);

            let result = search(&index, "(kernel) (\"cpe:/a:redhat:enterprise_linux:9\" in:package)");
            assert_eq!(result.0.len(), 1);
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
    async fn test_products_by_not_affected() {
        assert_search(|index| {
            let result = search(&index, "notAffected:\"cpe:/o:redhat:rhel_eus:8.6:*:baseos:*\"");
            assert_eq!(result.0.len(), 1);
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
            assert_eq!(result.0.len(), 4);
        });
    }

    #[tokio::test]
    async fn test_severity_count() {
        assert_search(|index| {
            let result = search(&index, "id:\"RHSA-2023:1441\"");
            assert_eq!(result.0.len(), 1);
            assert_eq!(result.0[0].document.cve_severity_count.len(), 1);
            assert_eq!(result.0[0].document.cve_severity_count["high"], 1);
        });
    }

    #[tokio::test]
    async fn test_sorting() {
        assert_search(|index| {
            let result = search(&index, "openssl -sort:severity");
            assert_eq!(result.0.len(), 2);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2023:1441");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:3408");
            assert!(result.0[0].document.advisory_date < result.0[1].document.advisory_date);

            let result = search(&index, "openssl sort:severity");
            assert_eq!(result.0.len(), 2);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2023:3408");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:1441");
            assert!(result.0[0].document.advisory_date > result.0[1].document.advisory_date);
        });
    }

    #[tokio::test]
    async fn test_sorting_noterms() {
        assert_search(|index| {
            let result = search(&index, "sort:release");
            assert_eq!(result.0.len(), 4);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2021:3029");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:1441");
            assert_eq!(result.0[2].document.advisory_id, "RHSA-2023:3408");
            assert_eq!(result.0[3].document.advisory_id, "RHSA-2023:4378");
            assert!(result.0[0].document.advisory_date < result.0[1].document.advisory_date);

            let result = search(&index, "-sort:release");
            assert_eq!(result.0.len(), 4);
            assert_eq!(result.0[0].document.advisory_id, "RHSA-2023:4378");
            assert_eq!(result.0[1].document.advisory_id, "RHSA-2023:3408");
            assert_eq!(result.0[2].document.advisory_id, "RHSA-2023:1441");
            assert_eq!(result.0[3].document.advisory_id, "RHSA-2021:3029");
            assert!(result.0[0].document.advisory_date > result.0[1].document.advisory_date);
        });
    }

    #[tokio::test]
    async fn test_metadata() {
        let now = OffsetDateTime::now_utc();
        assert_search(|index| {
            let result = index
                .search(
                    "",
                    0,
                    10000,
                    SearchOptions {
                        explain: false,
                        metadata: true,
                        summaries: true,
                    },
                )
                .unwrap();
            assert_eq!(result.0.len(), 4);
            for result in result.0 {
                assert!(result.metadata.is_some());
                let indexed_date = result.metadata.as_ref().unwrap()["indexed_timestamp"].clone();
                let value: &str = indexed_date["values"][0].as_str().unwrap();
                let indexed_date = OffsetDateTime::parse(value, &format_description::well_known::Rfc3339).unwrap();
                assert!(indexed_date >= now);
            }
        });
    }
}
