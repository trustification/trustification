pub mod license_exporter;
pub mod license_scanner;

pub struct SbomLicense {
    pub sbom_name: String,
    pub sbom_namespace: String,
    pub component_group: String,
    pub component_version: String,
    pub packages: Vec<SbomPackage>,
    pub is_spdx: bool,
}

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
    pub licenses: Vec<PackageLicense>,
}

pub struct PackageLicense {
    pub license_id: String,
    pub name: String,
    pub license_text: String,
    pub license_comment: String,
    pub is_license_ref: bool,
}
