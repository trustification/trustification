pub mod license_exporter;
pub mod license_scanner;

pub struct SbomLicense {
    pub sbom_name: String,
    pub sbom_namespace: String,
    pub component_group: String,
    pub component_version: String,
    pub packages: Vec<SbomPackage>,
    #[allow(dead_code)]
    pub is_spdx: bool,
}

#[allow(dead_code)]
pub struct SbomPackage {
    /// Package name
    pub name: String,
    /// Package version
    pub version: Option<String>,
    /// package package URL
    pub purl: String,
    pub other_reference: Vec<String>,
    /// package supplier
    pub supplier: Option<String>,
    /// List of all package license
    pub license_text: String,
    pub license_name: String,
    pub spdx_licenses: Vec<String>,
    pub spdx_license_exceptions: Vec<String>,
}

pub struct ExtractedLicensingInfos {
    pub license_id: String,
    pub name: String,
    pub extracted_text: String,
    pub comment: String,
}
