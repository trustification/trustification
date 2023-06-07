mod search;
use cyclonedx_bom::models::{component::Classification, hash::HashAlgorithm};
use search::*;

use sikula::prelude::*;

use spdx_rs::models::Algorithm;
use tracing::info;
use trustification_index::{
    create_boolean_query, primary2occur,
    tantivy::doc,
    tantivy::query::{Occur, Query},
    tantivy::schema::{Field, Schema, Term, FAST, STORED, STRING, TEXT},
    term2query, Document, Error as SearchError,
};

use core::str::FromStr;

pub struct Index {
    schema: Schema,
    fields: Fields,
}

pub enum SBOM {
    CycloneDX(cyclonedx_bom::prelude::Bom),
    SPDX(spdx_rs::models::SPDX),
}

impl SBOM {
    pub fn parse(data: &[u8]) -> Result<Self, serde_json::Error> {
        if let Ok(bom) = cyclonedx_bom::prelude::Bom::parse_from_json_v1_3(data) {
            Ok(SBOM::CycloneDX(bom))
        } else {
            let spdx = serde_json::from_slice::<spdx_rs::models::SPDX>(data).map_err(|e| {
                tracing::warn!("Error parsing SPDX: {:?}", e);
                e
            })?;
            Ok(SBOM::SPDX(spdx))
        }
    }
}

struct Fields {
    dependent: Field,
    purl: Field,
    ptype: Field,
    pnamespace: Field,
    pname: Field,
    pversion: Field,
    description: Field,
    sha256: Field,
    license: Field,
    qualifiers: Field,

    classifier: Field,
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
            dependent: schema.add_text_field("dependent", STRING | STORED),
            purl: schema.add_text_field("purl", STRING | FAST | STORED),
            ptype: schema.add_text_field("ptype", STRING),
            pnamespace: schema.add_text_field("pnamespace", STRING),
            pname: schema.add_text_field("pname", STRING),
            pversion: schema.add_text_field("pversion", STRING),
            description: schema.add_text_field("description", TEXT),
            sha256: schema.add_text_field("sha256", STRING),
            license: schema.add_text_field("license", STRING),
            qualifiers: schema.add_json_field("qualifiers", STRING),
            classifier: schema.add_text_field("classifier", STRING),
        };
        Self {
            schema: schema.build(),
            fields,
        }
    }

    fn index_spdx(&self, bom: &spdx_rs::models::SPDX) -> Result<Vec<Document>, SearchError> {
        tracing::info!("Indexing SPDX document");
        let mut documents = Vec::new();
        for package in &bom.package_information {
            let mut document = doc!();

            if let Some(comment) = &package.package_summary_description {
                document.add_text(self.fields.description, comment);
            }

            for r in package.external_reference.iter() {
                if r.reference_type == "purl" {
                    let purl = r.reference_locator.clone();
                    document.add_text(self.fields.purl, &purl);

                    if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                        document.add_text(self.fields.pname, package.name());
                        if let Some(namespace) = package.namespace() {
                            document.add_text(self.fields.pnamespace, namespace);
                        }

                        if let Some(version) = package.version() {
                            document.add_text(self.fields.pversion, version);
                        }

                        let mut qualifiers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
                        for entry in package.qualifiers().iter() {
                            if let Ok(value) = serde_json::from_str::<serde_json::Value>(entry.1) {
                                qualifiers.insert(entry.0.to_string(), value);
                            }
                        }
                        document.add_json_object(self.fields.qualifiers, qualifiers);
                        document.add_text(self.fields.ptype, package.ty());
                    }
                }
            }

            for sum in package.package_checksum.iter() {
                if sum.algorithm == Algorithm::SHA256 {
                    document.add_text(self.fields.sha256, &sum.value);
                }
            }

            document.add_text(self.fields.license, package.declared_license.to_string());

            documents.push(document);
        }
        Ok(documents)
    }

    fn index_cyclonedx(&self, bom: &cyclonedx_bom::prelude::Bom) -> Result<Vec<Document>, SearchError> {
        let mut documents = Vec::new();
        let mut parent = None;
        if let Some(metadata) = &bom.metadata {
            if let Some(component) = &metadata.component {
                documents.push(self.index_cyclonedx_component(component, None)?);
                if let Some(purl) = &component.purl {
                    parent.replace(purl.to_string());
                }
            }
        }

        if let Some(components) = &bom.components {
            for component in components.0.iter() {
                documents.push(self.index_cyclonedx_component(component, parent.as_deref())?);
            }
        }
        Ok(documents)
    }

    fn index_cyclonedx_component(
        &self,
        component: &cyclonedx_bom::prelude::Component,
        parent: Option<&str>,
    ) -> Result<Document, SearchError> {
        let mut document = doc!();

        if let Some(hashes) = &component.hashes {
            for hash in hashes.0.iter() {
                if hash.alg == HashAlgorithm::SHA256 {
                    document.add_text(self.fields.sha256, &hash.content.0);
                }
            }
        }

        if let Some(purl) = &component.purl {
            let purl = purl.to_string();
            document.add_text(self.fields.purl, &purl);

            if let Ok(package) = packageurl::PackageUrl::from_str(&purl) {
                document.add_text(self.fields.pname, package.name());
                if let Some(namespace) = package.namespace() {
                    document.add_text(self.fields.pnamespace, namespace);
                }

                if let Some(version) = package.version() {
                    document.add_text(self.fields.pversion, version);
                }

                let mut qualifiers: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
                for entry in package.qualifiers().iter() {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(entry.1) {
                        qualifiers.insert(entry.0.to_string(), value);
                    }
                }
                document.add_json_object(self.fields.qualifiers, qualifiers);
                document.add_text(self.fields.ptype, package.ty());
            }
        }

        if let Some(desc) = &component.description {
            document.add_text(self.fields.description, desc.to_string());
        }

        if let Some(licenses) = &component.licenses {
            use cyclonedx_bom::models::license::{LicenseChoice, LicenseIdentifier};
            let licenses: Vec<String> = licenses
                .0
                .iter()
                .map(|l| match l {
                    LicenseChoice::License(l) => match &l.license_identifier {
                        LicenseIdentifier::Name(s) => Some(s),
                        LicenseIdentifier::SpdxId(_) => None,
                    },
                    LicenseChoice::Expression(_) => None,
                })
                .filter(|s| s.is_some())
                .map(|m| m.unwrap().to_string())
                .collect();
            let license = licenses.join(" ");
            document.add_text(self.fields.license, license);
        }

        document.add_text(self.fields.classifier, component.component_type.to_string());

        if let Some(parent) = parent {
            document.add_text(self.fields.dependent, parent);
        }

        Ok(document)
    }

    fn resource2query(&self, resource: &Packages) -> Box<dyn Query> {
        match resource {
            Packages::Dependent(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.dependent, value);
                create_boolean_query(occur, term)
            }

            Packages::Purl(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.purl, value);
                create_boolean_query(occur, term)
            }

            Packages::Type(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.ptype, value);
                create_boolean_query(occur, term)
            }

            Packages::Namespace(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pnamespace, value);
                create_boolean_query(occur, term)
            }

            Packages::Name(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pname, value);
                create_boolean_query(occur, term)
            }

            Packages::Version(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.pversion, value);
                create_boolean_query(occur, term)
            }

            Packages::Description(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.description, value);
                create_boolean_query(occur, term)
            }

            Packages::Digest(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.sha256, value);
                create_boolean_query(occur, term)
            }

            Packages::License(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.license, value);
                create_boolean_query(occur, term)
            }

            Packages::Qualifier(primary) => {
                let (occur, value) = primary2occur(primary);
                let term = Term::from_field_text(self.fields.qualifiers, value);
                create_boolean_query(occur, term)
            }

            Packages::Application => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Application.to_string()),
            ),

            Packages::Library => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Library.to_string()),
            ),

            Packages::Framework => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Framework.to_string()),
            ),

            Packages::Container => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Container.to_string()),
            ),

            Packages::OperatingSystem => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::OperatingSystem.to_string()),
            ),

            Packages::Device => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Device.to_string()),
            ),
            Packages::Firmware => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::Firmware.to_string()),
            ),
            Packages::File => create_boolean_query(
                Occur::Must,
                Term::from_field_text(self.fields.classifier, &Classification::File.to_string()),
            ),
        }
    }
}

impl trustification_index::Index for Index {
    type MatchedDocument = String;
    type Document = SBOM;

    fn index_doc(&self, doc: &SBOM) -> Result<Vec<Document>, SearchError> {
        match doc {
            SBOM::CycloneDX(bom) => self.index_cyclonedx(bom),
            SBOM::SPDX(bom) => self.index_spdx(bom),
        }
    }

    fn schema(&self) -> Schema {
        self.schema.clone()
    }

    fn prepare_query(&self, q: &str) -> Result<Box<dyn Query>, SearchError> {
        let mut query = Packages::parse(q).map_err(|err| SearchError::Parser(err.to_string()))?;

        query.term = query.term.compact();

        info!("Query: {query:?}");

        let query = term2query(&query.term, &|resource| self.resource2query(resource));

        info!("Processed query: {:?}", query);
        Ok(query)
    }

    fn process_hit(&self, doc: Document) -> Result<Self::MatchedDocument, SearchError> {
        if let Some(Some(value)) = doc.get_first(self.fields.purl).map(|s| s.as_text()) {
            Ok(value.into())
        } else {
            Err(SearchError::NotFound)
        }
    }
}
