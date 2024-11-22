use crate::license::{PackageLicense, SbomLicense, SbomPackage};
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use bombastic_model::data::SBOM;
use cyclonedx_bom::models::license::{LicenseChoice, LicenseIdentifier};
use cyclonedx_bom::prelude::{Bom, Component, NormalizedString};
use http::StatusCode;
use spdx_expression::SpdxExpressionError;
use spdx_rs::models::SPDX;
use std::str::FromStr;
use trustification_common::error::ErrorInformation;

pub struct LicenseScanner {
    sbom: SBOM,
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

    pub fn scanner(&self) -> Result<SbomLicense, LicenseScannerError> {
        match &self.sbom {
            SBOM::SPDX(spdx_bom) => {
                let (sbom_name, all_packages) = self.handle_spdx_sbom(spdx_bom);
                let license_result = SbomLicense {
                    sbom_name: sbom_name.to_string(),
                    packages: all_packages,
                };

                Ok(license_result)
            }
            SBOM::CycloneDX(cyclonedx_bom) => {
                let (sbom_name, all_packages) = self.handle_cyclonedx_sbom(cyclonedx_bom)?;
                let license_result = SbomLicense {
                    sbom_name: sbom_name.to_string(),
                    packages: all_packages,
                };

                Ok(license_result)
            }
        }
    }

    fn handle_cyclonedx_sbom(&self, cyclonedx_bom: &Bom) -> Result<(String, Vec<SbomPackage>), LicenseScannerError> {
        let sbom_name = cyclonedx_bom
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.component.as_ref())
            .map(|component| (component.name.to_string()))
            .unwrap_or_default();

        let mut sbom_package_list = Vec::new();
        if let Some(cs) = &cyclonedx_bom.components {
            for component in cs.0.iter() {
                let package_name = component.name.to_string();
                let package_version = component
                    .version
                    .clone()
                    .unwrap_or_else(NormalizedString::default)
                    .to_string();
                let mut package_purl = String::default();

                if let Some(purl) = component.purl.clone() {
                    package_purl = purl.to_string();
                }
                let mut purl_namespace = String::default();
                let mut purl_version = String::default();
                // let mut purl_type = String::default();
                let mut purl_name = String::default();
                if let Ok(pl) = packageurl::PackageUrl::from_str(&package_purl) {
                    if let Some(namespace) = pl.namespace() {
                        purl_namespace = namespace.to_string();
                    }
                    if let Some(version) = pl.version() {
                        purl_version = version.to_string();
                    }
                    // purl_type = pl.ty().to_string();
                    purl_name = pl.name().to_string();
                }
                let mut supplier = String::default();
                if let Some(s) = component.supplier.clone() {
                    let ns = s.name;
                    supplier = ns.unwrap_or_else(NormalizedString::default).to_string();
                }

                let packages = self.handle_cyclonedx_sbom_component(component)?;
                sbom_package_list.push(SbomPackage {
                    name: package_name,
                    version: Some(package_version),
                    purl: package_purl,
                    purl_name,
                    purl_namespace,
                    purl_version,
                    supplier: Some(supplier),
                    licenses: packages,
                })
            }
        }
        Ok((sbom_name, sbom_package_list))
    }

    fn handle_cyclonedx_sbom_component(
        &self,
        component: &Component,
    ) -> Result<Vec<PackageLicense>, LicenseScannerError> {
        let mut licenses = Vec::new();
        if let Some(l) = component.licenses.as_ref() {
            for pl in l.0.clone() {
                match pl {
                    LicenseChoice::License(spl) => match spl.license_identifier {
                        LicenseIdentifier::SpdxId(spdx) => {
                            Self::fetch_license_from_spdx_expression(&mut licenses, spdx.to_string().as_str());
                        }
                        LicenseIdentifier::Name(not_spdx) => {
                            licenses.push(PackageLicense {
                                license_id: not_spdx.to_string(),
                                name: "".to_string(),
                                license_text: "".to_string(),
                                is_license_ref: false,
                                license_comment: "".to_string(),
                            });
                        }
                    },
                    LicenseChoice::Expression(spl_exp) => {
                        Self::fetch_license_from_spdx_expression(&mut licenses, spl_exp.to_string().as_str());
                    }
                }
            }
        };
        Ok(licenses)
    }

    fn fetch_license_from_spdx_expression(licenses: &mut Vec<PackageLicense>, spdx: &str) {
        let spdxs = spdx_expression::SpdxExpression::parse(spdx);
        match spdxs {
            Ok(s) => {
                for spdx in s.licenses() {
                    licenses.push(PackageLicense {
                        license_id: spdx.identifier.clone(),
                        name: "".to_string(),
                        license_text: "".to_string(),
                        is_license_ref: false,
                        license_comment: "".to_string(),
                    });
                }
            }
            Err(err) => {
                log::warn!("When an error occurs while parsing an SPDX expression.: {:?}", err)
            }
        }
    }

    fn handle_spdx_sbom(&self, spdx_bom: &SPDX) -> (String, Vec<SbomPackage>) {
        let sbom_name = spdx_bom.document_creation_information.document_name.clone();
        let mut all_packages = Vec::new();

        for pi in &spdx_bom.package_information {
            let package_name = &pi.package_name;
            let package_version = pi.package_version.clone();
            let package_url = &pi
                .external_reference
                .iter()
                .find(|r| r.reference_type == "purl")
                .map(|r| r.reference_locator.as_str())
                .unwrap_or("");

            let package_supplier = pi.package_supplier.clone();

            let mut spdx_ids = Vec::new();
            if let Some(license) = &pi.declared_license {
                for l in license.licenses() {
                    if l.license_ref {
                        let license_ref =
                            &spdx_bom
                                .other_licensing_information_detected
                                .iter()
                                .find(|extraced_license| {
                                    extraced_license.license_identifier.contains(l.identifier.as_str())
                                });

                        if let Some(license_info) = license_ref {
                            spdx_ids.push(PackageLicense {
                                license_id: license_info.license_identifier.to_string(),
                                name: license_info.license_name.to_string(),
                                license_text: license_info.extracted_text.to_string(),
                                is_license_ref: true,
                                license_comment: license_info
                                    .license_comment
                                    .as_ref()
                                    .map_or(String::new(), |v| v.to_string()),
                            });
                        }
                    } else {
                        spdx_ids.push(PackageLicense {
                            license_id: String::from(&l.identifier),
                            name: String::from(&l.identifier),
                            license_text: "".to_string(),
                            license_comment: "".to_string(),
                            is_license_ref: false,
                        });
                    }
                }
            }

            let mut purl_namespace = String::default();
            let mut purl_version = String::default();
            // let mut purl_type = String::default();
            let mut purl_name = String::default();

            if let Ok(pl) = packageurl::PackageUrl::from_str(package_url) {
                if let Some(namespace) = pl.namespace() {
                    purl_namespace = namespace.to_string();
                }
                if let Some(version) = pl.version() {
                    purl_version = version.to_string();
                }
                // purl_type = pl.ty().to_string();
                purl_name = pl.name().to_string();
            }
            let result = SbomPackage {
                name: String::from(package_name),
                version: package_version,
                purl: package_url.to_string(),
                purl_name,
                purl_namespace,
                purl_version,
                supplier: package_supplier,
                licenses: spdx_ids,
            };

            all_packages.push(result);
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

        let sbom_licenses = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let package_license = sbom_licenses
            .packages
            .iter()
            .find(|p| p.purl == "pkg:rpm/redhat/xorg-x11-fonts-Type1@7.5-9.el7?arch=noarch");

        if let Some(pl) = package_license {
            let ls: Vec<String> = pl.licenses.iter().map(|l| l.license_id.clone()).collect();
            assert_eq!(3, ls.len());
            assert!(ls.contains(&"MIT".to_string()));
            assert!(ls.contains(&"LicenseRef-Lucida".to_string()));
            assert!(ls.contains(&"LicenseRef-5".to_string()));
            for license in &pl.licenses {
                if license.license_id == "LicenseRef-Lucida" {
                    assert_eq!(license.license_text, "The license info found in the package meta data is: Lucida. See the specific package info in this SPDX document or the package itself for more details.");
                }
            }
        } else {
            panic!("the unit test failed");
        }
    }

    #[tokio::test]
    async fn test_cydx() {
        let sbom = load_sbom_file("../test-data/my-sbom.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let sbom_licenses = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let package_license = sbom_licenses
            .packages
            .iter()
            .find(|p| p.purl == "pkg:maven/io.quarkus/quarkus-arc@2.16.2.Final?type=jar");

        if let Some(pl) = package_license {
            let ls: Vec<String> = pl.licenses.iter().map(|l| l.license_id.clone()).collect();
            assert!(ls.contains(&"Apache-2.0".to_string()));
        } else {
            panic!("the unit test failed");
        }
    }
}
