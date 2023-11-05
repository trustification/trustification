use core::str::FromStr;

use bombastic_model::prelude::*;
use cyclonedx_bom::models::{
    component::Classification,
    hash::HashAlgorithm,
    license::{LicenseChoice, LicenseIdentifier},
};
use log::{debug, info, warn};
use sikula::{mir::Direction, prelude::*};
use spdx_rs::models::Algorithm;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use trustification_api::search::SearchOptions;
use trustification_index::{
    boost, create_boolean_query, create_date_query, create_string_query, field2str,
    metadata::doc2metadata,
    tantivy::{
        self,
        collector::TopDocs,
        doc,
        query::{AllQuery, BooleanQuery, TermQuery, TermSetQuery},
        query::{Occur, Query},
        schema::INDEXED,
        schema::{Field, Schema, Term, FAST, STORED, STRING, TEXT},
        store::ZstdCompressor,
        DateTime, DocAddress, DocId, IndexSettings, Order, Score, Searcher, SegmentReader, SnippetGenerator,
    },
    term2query, Document, Error as SearchError, SearchQuery,
};

pub struct Index {
    schema: Schema,
    fields: Fields,
}

pub struct PackageFields {
    name: Field,
    version: Field,
    desc: Field,
    purl: Field,
    cpe: Field,
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

struct Fields {
    dep: PackageFields,
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
            dep: PackageFields {
                name: schema.add_text_field("dep_name", FAST | STRING),
                purl: schema.add_text_field("dep_purl", FAST | STRING | STORED),
                version: schema.add_text_field("dep_version", STRING),
                desc: schema.add_text_field("dep_desc", TEXT),
                cpe: schema.add_text_field("dep_cpe", STRING | FAST | STORED),
                license: schema.add_text_field("dep_license", TEXT | STORED),
                supplier: schema.add_text_field("dep_supplier", STRING),
                classifier: schema.add_text_field("dep_classifier", STRING),
                sha256: schema.add_text_field("dep_sha256", STRING),
                purl_type: schema.add_text_field("dep_purl_type", STRING),
                purl_name: schema.add_text_field("dep_purl_name", FAST | STRING),
                purl_namespace: schema.add_text_field("dep_purl_namespace", STRING),
                purl_version: schema.add_text_field("dep_purl_version", STRING),
                purl_qualifiers: schema.add_text_field("dep_purl_qualifiers", STRING),
                purl_qualifiers_values: schema.add_text_field("dep_purl_qualifiers_values", STRING),
            },
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_spdx(&self, id: &str, bom: &spdx_rs::models::SPDX) -> Result<Document, SearchError> {
        debug!("Indexing SPDX document");

        let mut document = doc!();

        for package in &bom.package_information {
            if !bom
                .document_creation_information
                .document_describes
                .contains(&package.package_spdx_identifier)
            {
                Self::index_spdx_package(&mut document, package, &self.fields.dep);
            }
        }
        debug!("Indexed {:?}", document);
        Ok(document)
    }

    fn index_spdx_package(
        document: &mut Document,
        package: &spdx_rs::models::PackageInformation,
        fields: &PackageFields,
    ) {
        if let Some(comment) = &package.package_summary_description {
            document.add_text(fields.desc, comment);
        }
        for r in package.external_reference.iter() {
            if r.reference_type == "cpe22Type" {
                document.add_text(fields.cpe, &r.reference_locator);
            }
            if r.reference_type == "purl" {
                let purl = r.reference_locator.clone();
                document.add_text(fields.purl, &purl);

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
    }

    fn index_cyclonedx(&self, id: &str, bom: &cyclonedx_bom::prelude::Bom) -> Result<Document, SearchError> {
        let mut document = doc!();

        //To do
        Ok(document)
    }

    fn resource2query(&self, resource: &Packages) -> Box<dyn Query> {
        const PACKAGE_WEIGHT: f32 = 1.5;
        const CREATED_WEIGHT: f32 = 1.25;
        match resource {
            Packages::Id(value) => Box::new(TermQuery::new(
                Term::from_field_text(self.fields.sbom_id, value),
                Default::default(),
            )),
            Packages::Uid(value) => Box::new(TermQuery::new(
                Term::from_field_text(self.fields.sbom_uid, value),
                Default::default(),
            )),
            Packages::Package(primary) => boost(
                self.create_string_query(
                    &[
                        self.fields.sbom_name,
                        self.fields.sbom.name,
                        self.fields.sbom.purl,
                        self.fields.sbom.cpe,
                        self.fields.sbom.purl_name,
                    ],
                    primary,
                ),
                PACKAGE_WEIGHT,
            ),

            Packages::Type(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.sbom.purl_type,
                value,
            )])),

            Packages::Namespace(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.sbom.purl_namespace,
                value,
            )])),

            Packages::Created(ordered) => boost(
                create_date_query(&self.schema, self.fields.sbom_created, ordered),
                CREATED_WEIGHT,
            ),

            Packages::Version(value) => {
                self.create_string_query(&[self.fields.sbom.version, self.fields.sbom.purl_version], value)
            }

            Packages::Description(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.sbom.desc,
                value,
            )])),

            Packages::Digest(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.sbom.sha256,
                value,
            )])),

            Packages::License(value) => Box::new(TermSetQuery::new(vec![Term::from_field_text(
                self.fields.sbom.license,
                value,
            )])),

            Packages::Supplier(primary) => self.create_string_query(&[self.fields.sbom.supplier], primary),

            Packages::Qualifier(qualified) => {
                let mut qs = Vec::new();
                for qualifier in qualified.qualifier.0.iter() {
                    let exp = format!("{}={}", qualifier, qualified.expression);
                    let q = self.create_string_query(&[self.fields.sbom.purl_qualifiers], &Primary::Equal(&exp));
                    qs.push(q);
                }
                Box::new(BooleanQuery::union(qs))
            }

            Packages::Dependency(primary) => self.create_string_query(
                &[
                    self.fields.dep.name,
                    self.fields.dep.purl_name,
                    self.fields.dep.purl,
                    self.fields.dep.cpe,
                ],
                primary,
            ),

            Packages::Application => self.match_classifiers(Classification::Application),
            Packages::Library => self.match_classifiers(Classification::Library),
            Packages::Framework => self.match_classifiers(Classification::Framework),
            Packages::Container => self.match_classifiers(Classification::Container),
            Packages::OperatingSystem => self.match_classifiers(Classification::OperatingSystem),
            Packages::Device => self.match_classifiers(Classification::Device),
            Packages::Firmware => self.match_classifiers(Classification::Firmware),
            Packages::File => self.match_classifiers(Classification::File),
        }
    }

    fn create_string_query(&self, fields: &[Field], value: &Primary<'_>) -> Box<dyn Query> {
        let queries: Vec<Box<dyn Query>> = fields.iter().map(|f| create_string_query(*f, value)).collect();
        Box::new(BooleanQuery::union(queries))
    }

    fn match_classifiers(&self, classification: Classification) -> Box<dyn Query> {
        Box::new(BooleanQuery::union(vec![
            create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.sbom.classifier, &classification.to_string()),
            ),
            create_boolean_query(
                Occur::Should,
                Term::from_field_text(self.fields.dep.classifier, &classification.to_string()),
            ),
        ]))
    }
}

// impl trustification_index::Index for Index {
//     type MatchedDocument = SearchHit;
//
//     fn prepare_query(&self, q: &str) -> Result<SearchQuery, SearchError> {
//         let mut query = Packages::parse(q).map_err(|err| SearchError::QueryParser(err.to_string()))?;
//         query.term = query.term.compact();
//
//         debug!("Query: {:?}", query.term);
//
//         let mut sort_by = None;
//         if let Some(f) = query.sorting.first() {
//             match f.qualifier {
//                 PackagesSortable::Created => match f.direction {
//                     Direction::Descending => {
//                         sort_by.replace((self.fields.sbom_created, Order::Desc));
//                     }
//                     Direction::Ascending => {
//                         sort_by.replace((self.fields.sbom_created, Order::Asc));
//                     }
//                 },
//             }
//         }
//
//         let query = if query.term.is_empty() {
//             Box::new(AllQuery)
//         } else {
//             term2query(&query.term, &|resource| self.resource2query(resource))
//         };
//
//         debug!("Processed query: {:?}", query);
//         Ok(SearchQuery { query, sort_by })
//     }
//
//     fn search(
//         &self,
//         searcher: &Searcher,
//         query: &dyn Query,
//         offset: usize,
//         limit: usize,
//     ) -> Result<(Vec<(f32, DocAddress)>, usize), SearchError> {
//         let date_field = self.schema.get_field_name(self.fields.sbom_created).to_string();
//         let now = tantivy::DateTime::from_utc(OffsetDateTime::now_utc());
//         Ok(searcher.search(
//             query,
//             &(
//                 TopDocs::with_limit(limit)
//                     .and_offset(offset)
//                     .tweak_score(move |segment_reader: &SegmentReader| {
//                         let date_reader = segment_reader.fast_fields().date(&date_field);
//
//                         move |doc: DocId, original_score: Score| {
//                             let date_reader = date_reader.clone();
//                             let mut tweaked = original_score;
//                             // Now look at the date, normalize score between 0 and 1 (baseline 1970)
//                             if let Ok(Some(date)) = date_reader.map(|s| s.first(doc)) {
//                                 if date < now {
//                                     let normalized =
//                                         1.0 + (date.into_timestamp_secs() as f64 / now.into_timestamp_secs() as f64);
//                                     log::trace!("DATE score impact {} -> {}", tweaked, tweaked * (normalized as f32));
//                                     tweaked *= normalized as f32;
//                                 }
//                             }
//                             log::trace!("Tweaking from {} to {}", original_score, tweaked);
//                             tweaked
//                         }
//                     }),
//                 tantivy::collector::Count,
//             ),
//         )?)
//     }
//
//     fn process_hit(
//         &self,
//         doc_address: DocAddress,
//         score: f32,
//         searcher: &Searcher,
//         query: &dyn Query,
//         options: &SearchOptions,
//     ) -> Result<Self::MatchedDocument, SearchError> {
//         let doc = searcher.doc(doc_address)?;
//         let id = field2str(&self.schema, &doc, self.fields.sbom_id)?;
//         let uid = doc
//             .get_first(self.fields.sbom_uid)
//             .and_then(|s| s.as_text())
//             .map(ToString::to_string);
//         let name = field2str(&self.schema, &doc, self.fields.sbom_name)?;
//
//         let snippet_generator = SnippetGenerator::create(searcher, query, self.fields.sbom.desc)?;
//         let snippet = snippet_generator.snippet_from_doc(&doc).to_html();
//
//         let file_sha256 = doc
//             .get_first(self.fields.sbom_sha256)
//             .map(|s| s.as_text().unwrap_or(""))
//             .unwrap_or("");
//
//         let purl = doc
//             .get_first(self.fields.sbom.purl)
//             .map(|s| s.as_text().unwrap_or(""))
//             .map(|s| s.to_string());
//
//         let cpe = doc
//             .get_first(self.fields.sbom.cpe)
//             .map(|s| s.as_text().unwrap_or(""))
//             .map(|s| s.to_string());
//
//         let version = doc
//             .get_first(self.fields.sbom.version)
//             .map(|s| s.as_text().unwrap_or(""))
//             .unwrap_or("");
//
//         let sha256 = doc
//             .get_first(self.fields.sbom.sha256)
//             .map(|s| s.as_text().unwrap_or(""))
//             .unwrap_or("");
//
//         let license = doc
//             .get_first(self.fields.sbom.license)
//             .map(|s| s.as_text().unwrap_or("Unknown"))
//             .unwrap_or("Unknown");
//
//         let classifier = doc
//             .get_first(self.fields.sbom.classifier)
//             .map(|s| s.as_text().unwrap_or("Unknown"))
//             .unwrap_or("Unknown");
//
//         let supplier = doc
//             .get_first(self.fields.sbom.supplier)
//             .map(|s| s.as_text().unwrap_or("Unknown"))
//             .unwrap_or("Unknown");
//
//         let description = doc
//             .get_first(self.fields.sbom.desc)
//             .map(|s| s.as_text().unwrap_or(name))
//             .unwrap_or(name);
//
//         let created: time::OffsetDateTime = doc
//             .get_first(self.fields.sbom_created)
//             .map(|s| {
//                 s.as_date()
//                     .map(|d| d.into_utc())
//                     .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
//             })
//             .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
//
//         let dependencies: u64 = doc.get_all(self.fields.dep.purl).count() as u64;
//         let document = SearchDocument {
//             id: id.to_string(),
//             uid,
//             version: version.to_string(),
//             file_sha256: file_sha256.to_string(),
//             purl,
//             cpe,
//             name: name.to_string(),
//             sha256: sha256.to_string(),
//             license: license.to_string(),
//             classifier: classifier.to_string(),
//             supplier: supplier.to_string(),
//             snippet,
//             created,
//             description: description.to_string(),
//             dependencies,
//         };
//
//         let explanation: Option<serde_json::Value> = if options.explain {
//             match query.explain(searcher, doc_address) {
//                 Ok(explanation) => Some(serde_json::to_value(explanation).ok()).unwrap_or(None),
//                 Err(e) => {
//                     warn!("Error producing explanation for document {:?}: {:?}", doc_address, e);
//                     None
//                 }
//             }
//         } else {
//             None
//         };
//
//         let metadata = options.metadata.then(|| doc2metadata(&self.schema, &doc));
//
//         Ok(SearchHit {
//             document,
//             score,
//             explanation,
//             metadata,
//         })
//     }
// }

impl trustification_index::WriteIndex for Index {
    type Document = (SBOM, String);

    fn name(&self) -> &str {
        "sbom"
    }

    fn index_doc(&self, id: &str, (doc, sha256): &Self::Document) -> Result<Document, SearchError> {
        let mut doc = match doc {
            SBOM::CycloneDX(bom) => self.index_cyclonedx(id, bom)?,
            SBOM::SPDX(bom) => self.index_spdx(id, bom)?,
        };

        doc.add_text(self.fields.sbom_sha256, sha256);

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
            .get_field("sbom_id")
            .map(|f| Term::from_field_text(f, id))
            .unwrap()
    }
}
