use bombastic_model::prelude::*;
use core::str::FromStr;
use cyclonedx_bom::models::{
    hash::HashAlgorithm,
    license::{LicenseChoice, LicenseIdentifier},
};
use log::{debug, trace, warn};
use sikula::{mir::Direction, prelude::*};
use spdx_rs::models::Algorithm;
use time::OffsetDateTime;
use trustification_api::search::SearchOptions;
use trustification_index::{
    boost, create_date_query, create_string_query, field2str,
    metadata::doc2metadata,
    tantivy::{
        self,
        collector::TopDocs,
        doc,
        query::{AllQuery, BooleanQuery, Query, TermQuery, TermSetQuery},
        schema::{Field, Schema, Term, FAST, STORED, STRING, TEXT},
        store::ZstdCompressor,
        DateTime, DocAddress, DocId, IndexSettings, Order, Score, Searcher, SegmentReader,
    },
    term2query, Document, Error as SearchError, SearchQuery,
};

pub struct Index {
    schema: Schema,
    fields: Fields,
}

pub struct Fields {
    indexed_timestamp: Field,
    name: Field,
    version: Field,
    desc: Field,
    purl: Field,
    license: Field,
    supplier: Field,
    classifier: Field,
    sha256: Field,
    purl_type: Field,
    purl_name: Field,
    purl_namespace: Field,
    purl_version: Field,
    purl_qualifiers: Field,
    purl_qualifiers_values: Field,
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
            purl: schema.add_text_field("package_url", FAST | STRING | STORED),
            name: schema.add_text_field("package_name", FAST | STRING | STORED),
            version: schema.add_text_field("package_version", STRING | STORED),
            desc: schema.add_text_field("package_desc", TEXT | STORED),
            license: schema.add_text_field("package_license", TEXT | STORED),
            supplier: schema.add_text_field("package_supplier", STRING | STORED),
            classifier: schema.add_text_field("package_classifier", STRING | STORED),
            sha256: schema.add_text_field("package_sha256", STRING | STORED),
            purl_type: schema.add_text_field("package_url_type", STRING | STORED),
            purl_name: schema.add_text_field("package_url_name", FAST | STRING | STORED),
            purl_namespace: schema.add_text_field("package_url_namespace", STRING | STORED),
            purl_version: schema.add_text_field("package_url_version", STRING | STORED),
            purl_qualifiers: schema.add_text_field("package_url_qualifiers", STRING | STORED),
            purl_qualifiers_values: schema.add_text_field("package_url_qualifiers_values", STRING | STORED),
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_spdx(&self, bom: &spdx_rs::models::SPDX, sha256: &str) -> Result<Vec<(String, Document)>, SearchError> {
        debug!("Indexing Package from SPDX document");
        let mut documents: Vec<(String, Document)> = Vec::new();

        for package in &bom.package_information {
            if !bom
                .document_creation_information
                .document_describes
                .contains(&package.package_spdx_identifier)
            {
                Self::index_spdx_package(&mut documents, package, &self.fields, sha256);
            }
        }
        trace!("Indexed {:?}", documents);
        Ok(documents)
    }

    fn index_spdx_package(
        documents: &mut Vec<(String, Document)>,
        package: &spdx_rs::models::PackageInformation,
        fields: &Fields,
        sha256: &str,
    ) {
        let mut document = doc!();
        document.add_text(fields.sha256, sha256);
        document.add_date(fields.indexed_timestamp, DateTime::from_utc(OffsetDateTime::now_utc()));

        if let Some(comment) = &package.package_summary_description {
            document.add_text(fields.desc, comment);
        }

        let mut package_id = "".to_string();
        for r in package.external_reference.iter() {
            if r.reference_type == "purl" {
                let purl = r.reference_locator.clone();
                package_id = purl.clone();

                if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                    document.add_text(fields.purl_name, package.name());
                    if let Some(namespace) = package.namespace() {
                        document.add_text(fields.purl_namespace, namespace);
                    }

                    if let Some(version) = package.version() {
                        document.add_text(fields.purl_version, version);
                    }

                    for entry in package.qualifiers().iter() {
                        document.add_text(fields.purl_qualifiers, format!("{}={}", entry.0, entry.1));
                        document.add_text(fields.purl_qualifiers_values, entry.1);
                    }

                    document.add_text(fields.purl_type, package.ty());
                }
            }
        }

        document.add_text(fields.purl, &package_id);
        document.add_text(fields.name, &package.package_name);
        if let Some(version) = &package.package_version {
            document.add_text(fields.version, version);
        }

        for sum in package.package_checksum.iter() {
            if sum.algorithm == Algorithm::SHA256 {
                document.add_text(fields.sha256, &sum.value);
            }
        }

        if let Some(license) = &package.declared_license {
            document.add_text(fields.license, license.to_string());
        }

        if let Some(supplier) = &package.package_supplier {
            document.add_text(fields.supplier, supplier);
        }

        // Only add packages with purls
        if !package_id.is_empty() {
            documents.push((package_id, document));
        }
    }

    fn index_cyclonedx(
        &self,
        bom: &cyclonedx_bom::prelude::Bom,
        sha256: &str,
    ) -> Result<Vec<(String, Document)>, SearchError> {
        let mut documents: Vec<(String, Document)> = Vec::new();

        if let Some(components) = &bom.components {
            for component in components.0.iter() {
                Self::index_cyclonedx_component(&mut documents, component, &self.fields, sha256);
            }
        }

        Ok(documents)
    }

    fn index_cyclonedx_component(
        documents: &mut Vec<(String, Document)>,
        component: &cyclonedx_bom::prelude::Component,
        fields: &Fields,
        sha256: &str,
    ) {
        let mut document = doc!();
        document.add_text(fields.sha256, sha256);
        document.add_date(fields.indexed_timestamp, DateTime::from_utc(OffsetDateTime::now_utc()));
        if let Some(hashes) = &component.hashes {
            for hash in hashes.0.iter() {
                if hash.alg == HashAlgorithm::SHA256 {
                    document.add_text(fields.sha256, &hash.content.0);
                }
            }
        }

        document.add_text(fields.name, component.name.to_string());
        document.add_text(fields.version, component.version.to_string());
        let mut package_id = "".to_string();
        if let Some(purl) = &component.purl {
            let purl = purl.to_string();
            package_id = purl.clone();
            document.add_text(fields.purl, &purl);

            if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                log::warn!("package is {}", package.clone());
                document.add_text(fields.purl_name, package.name());
                if let Some(namespace) = package.namespace() {
                    document.add_text(fields.purl_namespace, namespace);
                }

                if let Some(version) = package.version() {
                    document.add_text(fields.purl_version, version);
                }

                for entry in package.qualifiers().iter() {
                    document.add_text(fields.purl_qualifiers, entry.1);
                }
                document.add_text(fields.purl_type, package.ty());
            }
        }

        if let Some(desc) = &component.description {
            document.add_text(fields.desc, desc.to_string());
        }

        if let Some(licenses) = &component.licenses {
            licenses.0.iter().for_each(|l| match l {
                LicenseChoice::License(l) => match &l.license_identifier {
                    LicenseIdentifier::Name(s) => {
                        document.add_text(fields.license, s.to_string());
                    }
                    LicenseIdentifier::SpdxId(_) => (),
                },
                LicenseChoice::Expression(_) => (),
            });
        }

        document.add_text(fields.classifier, component.component_type.to_string());

        // Only add packages with purls
        if !package_id.is_empty() {
            documents.push((package_id, document));
        }
    }

    fn resource2query(&self, resource: &PackageInfo) -> Box<dyn Query> {
        // const PACKAGE_WEIGHT: f32 = 1.5;
        const CREATED_WEIGHT: f32 = 1.25;
        match resource {
            PackageInfo::Purl(value) => self.create_string_query(&[self.fields.purl], value),

            PackageInfo::Type(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.purl_type,
                value,
            )])),

            PackageInfo::Version(value) => {
                self.create_string_query(&[self.fields.version, self.fields.purl_version], value)
            }

            PackageInfo::Description(value) => {
                Box::new(TermSetQuery::new(vec![Term::from_field_text(self.fields.desc, value)]))
            }

            PackageInfo::License(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.license,
                value,
            )])),

            PackageInfo::Supplier(primary) => self.create_string_query(&[self.fields.supplier], primary),

            PackageInfo::Created(ordered) => boost(
                create_date_query(&self.schema, self.fields.indexed_timestamp, ordered),
                CREATED_WEIGHT,
            ),

            PackageInfo::Name(value) => self.create_string_query(&[self.fields.purl_name], value),
            PackageInfo::Namespace(value) => self.create_string_query(&[self.fields.purl_namespace], value),

            PackageInfo::Qualifier(value) => {
                let value = format!("{}={}", value.qualifier, value.expression);
                Box::new(TermQuery::new(
                    Term::from_field_text(self.fields.purl_qualifiers, &value),
                    Default::default(),
                ))
            }
        }
    }

    fn create_string_query(&self, fields: &[Field], value: &Primary<'_>) -> Box<dyn Query> {
        let queries: Vec<Box<dyn Query>> = fields.iter().map(|f| create_string_query(*f, value)).collect();
        Box::new(BooleanQuery::union(queries))
    }
}

impl trustification_index::Index for Index {
    type MatchedDocument = SearchPackageHit;

    fn prepare_query(&self, q: &str) -> Result<SearchQuery, SearchError> {
        let mut query = PackageInfo::parse(q).map_err(|err| SearchError::QueryParser(err.to_string()))?;
        query.term = query.term.compact();

        debug!("Query: {:?}", query.term);

        let mut sort_by = None;
        if let Some(f) = query.sorting.first() {
            match f.qualifier {
                PackageInfoSortable::Created => match f.direction {
                    Direction::Descending => {
                        sort_by.replace((self.fields.indexed_timestamp, Order::Desc));
                    }
                    Direction::Ascending => {
                        sort_by.replace((self.fields.indexed_timestamp, Order::Asc));
                    }
                },
            }
        }

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
        let date_field = self.schema.get_field_name(self.fields.indexed_timestamp).to_string();
        let now = tantivy::DateTime::from_utc(OffsetDateTime::now_utc());
        Ok(searcher.search(
            query,
            &(
                TopDocs::with_limit(limit)
                    .and_offset(offset)
                    .tweak_score(move |segment_reader: &SegmentReader| {
                        let date_reader = segment_reader.fast_fields().date(&date_field);

                        move |doc: DocId, original_score: Score| {
                            let date_reader = date_reader.clone();
                            let mut tweaked = original_score;
                            // Now look at the date, normalize score between 0 and 1 (baseline 1970)
                            if let Ok(Some(date)) = date_reader.map(|s| s.first(doc)) {
                                if date < now {
                                    let normalized =
                                        1.0 + (date.into_timestamp_secs() as f64 / now.into_timestamp_secs() as f64);
                                    log::trace!("DATE score impact {} -> {}", tweaked, tweaked * (normalized as f32));
                                    tweaked *= normalized as f32;
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
        let purl = field2str(&self.schema, &doc, self.fields.purl)?;
        let name = field2str(&self.schema, &doc, self.fields.name)?;

        let version = doc
            .get_first(self.fields.version)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let sha256 = doc
            .get_first(self.fields.sha256)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let license = doc
            .get_first(self.fields.license)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let classifier = doc
            .get_first(self.fields.classifier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let supplier = doc
            .get_first(self.fields.supplier)
            .map(|s| s.as_text().unwrap_or("Unknown"))
            .unwrap_or("Unknown");

        let description = doc
            .get_first(self.fields.desc)
            .map(|s| s.as_text().unwrap_or(name))
            .unwrap_or(name);

        let purl_type = doc
            .get_first(self.fields.purl_type)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let purl_name = doc
            .get_first(self.fields.purl_name)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or(name);

        let purl_namespace = doc
            .get_first(self.fields.purl_namespace)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let purl_version = doc
            .get_first(self.fields.purl_version)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let purl_qualifiers = doc
            .get_first(self.fields.purl_qualifiers)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let purl_qualifiers_values = doc
            .get_first(self.fields.purl_qualifiers_values)
            .map(|s| s.as_text().unwrap_or(""))
            .unwrap_or("");

        let document = SearchPackageDocument {
            version: version.to_string(),
            purl: purl.to_string(),
            name: name.to_string(),
            sha256: sha256.to_string(),
            license: license.to_string(),
            classifier: classifier.to_string(),
            supplier: supplier.to_string(),
            purl_type: purl_type.to_string(),
            purl_name: purl_name.to_string(),
            purl_namespace: purl_namespace.to_string(),
            purl_version: purl_version.to_string(),
            purl_qualifiers: purl_qualifiers.to_string(),
            description: description.to_string(),
            purl_qualifiers_values: purl_qualifiers_values.to_string(),
        };

        let explanation: Option<serde_json::Value> = if options.explain {
            match query.explain(searcher, doc_address) {
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

        Ok(SearchPackageHit {
            document,
            score,
            explanation,
            metadata,
        })
    }
}

impl trustification_index::WriteIndex for Index {
    type Document = (SBOM, String);

    fn name(&self) -> &str {
        "package"
    }

    #[allow(unused_variables)]
    fn index_doc(&self, _id: &str, (doc, sha256): &Self::Document) -> Result<Vec<(String, Document)>, SearchError> {
        let doc = match doc {
            SBOM::CycloneDX(bom) => self.index_cyclonedx(bom, sha256)?,
            SBOM::SPDX(bom) => self.index_spdx(bom, sha256)?,
        };

        Ok(doc)
    }

    fn parse_doc(&self, data: &[u8]) -> Result<Self::Document, SearchError> {
        let sha256 = sha256::digest(data);
        SBOM::parse(data)
            .map_err(|e| SearchError::DocParser(e.to_string()))
            .map(|doc| (doc, sha256))
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
            .get_field("package_url")
            .map(|f| Term::from_field_text(f, id))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use sbom_walker::Sbom;
    use std::path::Path;
    use trustification_index::{IndexStore, IndexWriter};

    use super::*;

    const TESTDATA: &[&str] = &["../testdata/ubi9-sbom.json", "../testdata/ubi9-sbom.json"];

    fn load_valid_file(store: &mut IndexStore<Index>, writer: &mut IndexWriter, path: impl AsRef<Path>) {
        let data = std::fs::read(&path).unwrap();
        // ensure it parses
        Sbom::try_parse_any(&data).unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display()));
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

    fn search(index: &IndexStore<Index>, query: &str) -> (Vec<SearchPackageHit>, usize) {
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
    async fn test_search_packages_empty_query() {
        assert_search(|index| {
            let result = search(&index, "");
            assert_eq!(result.0.len(), 617);
        });
    }

    #[tokio::test]
    async fn test_search_packages_by_purl() {
        assert_search(|index| {
            let result = search(&index, "purl:\"pkg:rpm/redhat/libdnf@0.67.0-3.el9?arch=aarch64\"");
            assert_eq!(result.0.len(), 1);
        });
    }

    #[tokio::test]
    async fn test_search_packages_by_supplier() {
        assert_search(|index| {
            let result = search(&index, "supplier:\"Organization: Red Hat\"");
            assert_eq!(result.0.len(), 617);
        });
    }

    #[tokio::test]
    async fn test_search_packages_by_package_type() {
        assert_search(|index| {
            let result = search(&index, "type:rpm");
            assert_eq!(result.0.len(), 613);
        });
    }

    #[tokio::test]
    async fn test_search_packages_by_name() {
        assert_search(|index| {
            let result = search(&index, "redhat.dbus");
            assert_eq!(result.0.len(), 13);
        });
    }
}
