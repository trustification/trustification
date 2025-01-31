use crate::license::{ExtractedLicensingInfos, SbomLicense, SbomPackage};
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use bombastic_model::data::SBOM;
use cyclonedx_bom::models::license::{LicenseChoice, LicenseIdentifier};
use cyclonedx_bom::prelude::{Bom, Component, NormalizedString};
use http::StatusCode;
use spdx_expression::SpdxExpressionError;
use spdx_rs::models::{ExternalPackageReferenceCategory, SPDX};
use trustification_common::error::ErrorInformation;

pub struct LicenseScanner {
    sbom: SBOM,
}

#[derive(Default)]
struct SpdxLicenses {
    pub license_text: String,
    pub license_name: String,
    pub spdx_licenses: Vec<String>,
    pub spdx_license_exceptions: Vec<String>,
}
#[derive(Debug, thiserror::Error)]
pub enum LicenseScannerError {
    #[error("failed to parse license data: {0}")]
    SpdxExpression(#[from] SpdxExpressionError),
}

impl ResponseError for LicenseScannerError {
    fn status_code(&self) -> StatusCode {
        match self {
            LicenseScannerError::SpdxExpression(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());

        match self {
            LicenseScannerError::SpdxExpression(spdx) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", spdx),
                details: spdx.to_string(),
            }),
        }
    }
}

impl LicenseScanner {
    pub fn new(sbom: SBOM) -> Self {
        LicenseScanner { sbom }
    }

    pub fn scanner(&self) -> Result<(SbomLicense, Vec<ExtractedLicensingInfos>), LicenseScannerError> {
        match &self.sbom {
            SBOM::SPDX(spdx_bom) => {
                let (sbom_name, all_packages) = self.handle_spdx_sbom(spdx_bom);
                let license_result = SbomLicense {
                    sbom_name: sbom_name.to_string(),
                    sbom_namespace: String::from(&spdx_bom.document_creation_information.spdx_document_namespace),
                    component_group: "".to_string(),
                    component_version: "".to_string(),
                    packages: all_packages,
                    is_spdx: true,
                };
                let extracted_licensing_infos = spdx_bom
                    .other_licensing_information_detected
                    .iter()
                    .map(|oli| ExtractedLicensingInfos {
                        license_id: oli.license_identifier.clone(),
                        name: oli.license_name.clone(),
                        extracted_text: oli.extracted_text.clone(),
                        comment: oli.license_comment.clone().unwrap_or_default(),
                    })
                    .collect();
                Ok((license_result, extracted_licensing_infos))
            }
            SBOM::CycloneDX(cyclonedx_bom) => {
                let (name, group, version, all_packages) = self.handle_cyclonedx_sbom(cyclonedx_bom)?;
                let license_result = SbomLicense {
                    sbom_name: name.to_string(),
                    sbom_namespace: "".to_string(),
                    component_group: group,
                    component_version: version,
                    packages: all_packages,
                    is_spdx: false,
                };

                Ok((license_result, vec![]))
            }
        }
    }

    fn handle_cyclonedx_sbom(
        &self,
        cyclonedx_bom: &Bom,
    ) -> Result<(String, String, String, Vec<SbomPackage>), LicenseScannerError> {
        let mut name = String::default();
        let mut version = String::default();
        let mut group = String::default();
        let mut sbom_package_list = Vec::new();
        if let Some(metadata) = &cyclonedx_bom.metadata {
            if let Some(component) = &metadata.component {
                name = String::from(&component.name.to_string());
                if let Some(v) = &component.version {
                    version = String::from(&v.to_string());
                }
                if let Some(g) = &component.group {
                    group = String::from(&g.to_string());
                }
                // https://issues.redhat.com/browse/TC-2213
                // first of all add the metadata.component
                let (spdx_licenses, other_reference) = self.handle_cyclonedx_sbom_component(component)?;
                spdx_licenses.into_iter().for_each(|spdx_license| {
                    sbom_package_list.push(SbomPackage {
                        name: name.clone(),
                        version: Some(version.clone()),
                        purl: Self::cyclonedx_get_purl(component),
                        other_reference: other_reference.clone(),
                        supplier: Some(Self::cyclondedx_get_supplier(component)),
                        license_text: spdx_license.license_text,
                        // https://issues.redhat.com/browse/TC-2160?focusedId=26502788&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-26502788
                        license_name: spdx_license.license_name,
                        spdx_licenses: spdx_license.spdx_licenses,
                        spdx_license_exceptions: spdx_license.spdx_license_exceptions,
                    });
                });
            }
        }

        if let Some(cs) = &cyclonedx_bom.components {
            for component in cs.0.iter() {
                let package_name = component.name.to_string();
                let package_version = component
                    .version
                    .clone()
                    .unwrap_or_else(NormalizedString::default)
                    .to_string();

                let (spdx_licenses, other_reference) = self.handle_cyclonedx_sbom_component(component)?;
                spdx_licenses.into_iter().for_each(|spdx_license| {
                    sbom_package_list.push(SbomPackage {
                        name: package_name.clone(),
                        version: Some(package_version.clone()),
                        purl: Self::cyclonedx_get_purl(component),
                        other_reference: other_reference.clone(),
                        supplier: Some(Self::cyclondedx_get_supplier(component)),
                        license_text: spdx_license.license_text,
                        // https://issues.redhat.com/browse/TC-2160?focusedId=26502788&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-26502788
                        license_name: spdx_license.license_name,
                        spdx_licenses: spdx_license.spdx_licenses,
                        spdx_license_exceptions: spdx_license.spdx_license_exceptions,
                    });
                });
            }
        }
        Ok((name, group, version, sbom_package_list))
    }

    fn handle_cyclonedx_sbom_component(
        &self,
        component: &Component,
    ) -> Result<(Vec<SpdxLicenses>, Vec<String>), LicenseScannerError> {
        let other_reference = if let Some(cpe) = component.cpe.clone() {
            cpe.to_string()
        } else {
            String::default()
        };
        let other_reference = vec![other_reference];

        let mut spdx_licenses: Vec<SpdxLicenses> = vec![];
        if let Some(licenses) = component.licenses.as_ref() {
            licenses.0.clone().into_iter().for_each(|license| {
                spdx_licenses.push(match license {
                    LicenseChoice::License(spl) => match spl.license_identifier {
                        LicenseIdentifier::SpdxId(spdx) => {
                            let spdx_licenses = vec![spdx.to_string()];
                            let spdx_license_exceptions = vec![];
                            SpdxLicenses {
                                license_text: "".to_string(),
                                license_name: "".to_string(),
                                spdx_licenses,
                                spdx_license_exceptions,
                            }
                        }
                        LicenseIdentifier::Name(not_spdx) => {
                            let spdx_licenses = vec![];
                            let spdx_license_exceptions = vec![];
                            SpdxLicenses {
                                license_text: "".to_string(),
                                license_name: not_spdx.to_string(),
                                spdx_licenses,
                                spdx_license_exceptions,
                            }
                        }
                    },
                    LicenseChoice::Expression(spl_exp) => {
                        SpdxLicenses {
                            license_text: spl_exp.clone().to_string(),
                            license_name: "".to_string(),
                            // https://issues.redhat.com/browse/TC-2160?focusedId=26502788&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-26502788
                            spdx_licenses: vec![],
                            spdx_license_exceptions: vec![],
                        }
                    }
                });
            });
        };
        Ok((spdx_licenses, other_reference))
    }

    fn cyclonedx_get_purl(component: &Component) -> String {
        match component.purl {
            Some(ref purl) => purl.to_string(),
            None => String::default(),
        }
    }

    fn cyclondedx_get_supplier(component: &Component) -> String {
        match component.supplier {
            Some(ref supplier) => supplier
                .name
                .clone()
                .unwrap_or_else(NormalizedString::default)
                .to_string(),
            None => String::default(),
        }
    }

    fn handle_spdx_sbom(&self, spdx_bom: &SPDX) -> (String, Vec<SbomPackage>) {
        let sbom_name = spdx_bom.document_creation_information.document_name.clone();
        let mut all_packages = Vec::new();

        for pi in &spdx_bom.package_information {
            let package_name = &pi.package_name;
            let package_version = pi.package_version.clone();

            let reference_refs = &pi.external_reference;
            let package_url = reference_refs
                .iter()
                .find(|r| r.reference_category == ExternalPackageReferenceCategory::PackageManager)
                .map(|r| r.reference_locator.as_str())
                .unwrap_or("");

            let other_references: &Vec<String> = &reference_refs
                .iter()
                .filter(|r| r.reference_category != ExternalPackageReferenceCategory::PackageManager)
                .map(|r| r.reference_locator.clone())
                .collect();

            let package_supplier = pi.package_supplier.clone();

            if let Some(license) = &pi.declared_license {
                let result = SbomPackage {
                    name: String::from(package_name),
                    version: package_version.clone(),
                    purl: String::from(package_url),
                    other_reference: other_references.clone(),
                    supplier: package_supplier,
                    license_text: license.to_string(),
                    license_name: "".to_string(),
                    // https://issues.redhat.com/browse/TC-2150
                    // it's fine to not collect the single licenses when dealing with an expression
                    spdx_licenses: vec![],
                    spdx_license_exceptions: license.exceptions().iter().map(|l| l.to_string()).clone().collect(),
                };

                all_packages.push(result)
            }
        }
        (sbom_name, all_packages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bombastic_model::data::SBOM;
    use std::path::Path;

    fn load_sbom_file(path: impl AsRef<Path>) -> Result<SBOM, anyhow::Error> {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read file failed {:?}", e));
        Ok(SBOM::parse(&data).unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display())))
    }

    #[tokio::test]
    async fn test_spdx() {
        let sbom =
            load_sbom_file("../test-data/rhel-7.9.z.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_license_infos) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let package_license = sbom_licenses
            .packages
            .iter()
            .find(|p| p.purl == "pkg:rpm/redhat/xorg-x11-fonts-Type1@7.5-9.el7?arch=noarch");

        if let Some(pl) = package_license {
            assert!(pl.spdx_licenses.is_empty());

            assert!(extracted_license_infos
                .iter()
                .any(|e| e.license_id == "LicenseRef-Lucida"))
        } else {
            panic!("the unit test failed");
        }
    }

    #[tokio::test]
    async fn test_cydx() {
        let sbom = load_sbom_file("../test-data/my-sbom.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_license_infos) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        assert_eq!(0, extracted_license_infos.len());
        let package_license = sbom_licenses
            .packages
            .iter()
            .find(|p| p.purl == "pkg:maven/io.quarkus/quarkus-arc@2.16.2.Final?type=jar");

        if let Some(pl) = package_license {
            assert!(pl.spdx_licenses.contains(&"Apache-2.0".to_string()));
            assert_eq!(0, pl.spdx_license_exceptions.len());
        } else {
            panic!("the unit test failed");
        }

        // https://issues.redhat.com/browse/TC-2187
        // Test a component with multiple elements in the `licenses` array
        let package_licenses = sbom_licenses
            .packages
            .into_iter()
            .filter(|p| p.purl == "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar")
            .collect::<Vec<_>>();

        assert_eq!(2, package_licenses.len());
        assert!(package_licenses[0].spdx_licenses.contains(&"EPL-2.0".to_string()));
        assert!(package_licenses[1]
            .spdx_licenses
            .contains(&"GPL-2.0-with-classpath-exception".to_string()));
        assert_eq!(0, package_licenses[1].spdx_license_exceptions.len());
    }

    #[tokio::test]
    async fn test_cydx_with_cpe() {
        let sbom = load_sbom_file("../test-data/tc_1730_license_escape.json")
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_license_infos) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        assert_eq!(0, extracted_license_infos.len());
        let package_license = sbom_licenses
            .packages
            .iter()
            .find(|p| p.purl == "pkg:rpm/rhel/llvm-libs@17.0.6-5.el9?arch=x86_64&upstream=llvm-17.0.6-5.el9.src.rpm&distro=rhel-9.4");

        if let Some(license) = package_license {
            assert_eq!(license.license_text, "Apache-2.0 WITH LLVM-exception OR NCSA");
            assert!(license.spdx_license_exceptions.is_empty());
            assert!(license.spdx_licenses.is_empty());
            assert_eq!(1, license.other_reference.len());
            assert_eq!(
                "cpe:2.3:a:llvm-libs:llvm-libs:17.0.6-5.el9:*:*:*:*:*:*:*",
                license.other_reference[0]
            );
        } else {
            panic!("test failed");
        }
    }
}
