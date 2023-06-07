#![allow(dead_code)]

use tracing::info;

#[allow(clippy::upper_case_acronyms)]
pub enum SBOM<'a> {
    SPDX {
        raw: &'a [u8],
        purl: Option<String>,
        sha256: Option<String>,
    },
    CycloneDX {
        raw: &'a [u8],
        purl: Option<String>,
        sha256: Option<String>,
    },
}

// TODO:
// * Use serde instead of raw JSON to avoid copying
// * Or let seedwing handle it
impl<'a> SBOM<'a> {
    pub fn raw(&self) -> &[u8] {
        match self {
            Self::SPDX {
                raw,
                purl: _,
                sha256: _,
            } => raw,
            Self::CycloneDX {
                raw,
                purl: _,
                sha256: _,
            } => raw,
        }
    }

    pub fn parse(data: &'a [u8]) -> Result<Self, anyhow::Error> {
        match serde_json::from_slice::<cyclonedx::SBOM>(data) {
            Ok(bom) => {
                let purl = bom.metadata.component.purl;
                let mut sha256 = None;
                for tool in bom.metadata.tools {
                    for hash in tool.hashes {
                        // TODO: Better way to do this...
                        if hash.alg == "SHA-256" {
                            sha256.replace(hash.content);
                            break;
                        }
                    }
                }
                return Ok(Self::CycloneDX {
                    raw: data,
                    purl,
                    sha256,
                });
            }
            Err(err) => {
                info!("Failed to parse as CycloneDX: {err}");
            }
        }

        match serde_json::from_slice::<spdx::SBOM>(data) {
            Ok(bom) => {
                let mut purl = None;
                let mut sha256 = None;
                if let Some(describes) = bom.document_describes.first() {
                    let mut package = None;
                    for p in bom.packages {
                        if p.spdx_id.eq(describes) {
                            package.replace(p);
                            break;
                        }
                    }

                    if let Some(package) = package {
                        for r in package.external_refs {
                            if r.ref_type == "purl" {
                                purl.replace(r.locator);
                                break;
                            }
                        }

                        for checksum in package.checksums {
                            // TODO: Better way to do this...
                            if checksum.algorithm == "SHA256" {
                                sha256.replace(checksum.value);
                                break;
                            }
                        }
                    }
                }
                return Ok(Self::SPDX {
                    raw: data,
                    purl,
                    sha256,
                });
            }
            Err(err) => {
                info!("Failed to parse as SPDX: {err}");
            }
        }

        Err(anyhow::anyhow!("Unknown format"))
    }

    pub fn purl(&self) -> Option<String> {
        match self {
            Self::CycloneDX {
                raw: _,
                purl,
                sha256: _,
            } => purl.clone(),
            Self::SPDX {
                raw: _,
                purl,
                sha256: _,
            } => purl.clone(),
        }
    }

    pub fn sha256(&self) -> Option<String> {
        match self {
            Self::CycloneDX {
                raw: _,
                purl: _,
                sha256,
            } => sha256.clone(),
            Self::SPDX {
                raw: _,
                purl: _,
                sha256,
            } => sha256.clone(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
mod cyclonedx {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct SBOM {
        pub metadata: Meta,
    }

    #[derive(Deserialize)]
    pub struct Meta {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub tools: Vec<Tool>,
        pub component: Component,
    }

    #[derive(Deserialize)]
    pub struct Tool {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hashes: Vec<Hash>,
    }

    #[derive(Deserialize)]
    pub struct Hash {
        pub alg: String,
        pub content: String,
    }

    #[derive(Deserialize)]
    pub struct Component {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub purl: Option<String>,
    }
}

#[allow(clippy::upper_case_acronyms)]
mod spdx {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct SBOM {
        #[serde(rename = "SPDXID")]
        pub spdx_id: String,
        #[serde(rename = "documentDescribes", default, skip_serializing_if = "Vec::is_empty")]
        pub document_describes: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub packages: Vec<Package>,
    }

    #[derive(Deserialize)]
    pub struct Package {
        #[serde(rename = "SPDXID")]
        pub spdx_id: String,
        #[serde(rename = "externalRefs", default, skip_serializing_if = "Vec::is_empty")]
        pub external_refs: Vec<External>,

        #[serde(rename = "checksums", default, skip_serializing_if = "Vec::is_empty")]
        pub checksums: Vec<Checksum>,
    }

    #[derive(Deserialize)]
    pub struct External {
        #[serde(rename = "referenceLocator")]
        pub locator: String,

        #[serde(rename = "referenceType")]
        pub ref_type: String,
    }

    #[derive(Deserialize)]
    pub struct Checksum {
        #[serde(rename = "algorithm")]
        pub algorithm: String,

        #[serde(rename = "checksumValue")]
        pub value: String,
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::SBOM;

    #[test]
    fn parse_spdx() {
        let data = include_bytes!("../../testdata/ubi9-sbom.json");
        let sbom = SBOM::parse(data).unwrap();
        assert_eq!(
            "pkg:oci/ubi9@sha256:cb303404e576ff5528d4f08b12ad85fab8f61fa9e5dba67b37b119db24865df3?repository_url=registry.redhat.io/ubi9&tag=9.1.0-1782",
            sbom.purl().unwrap()
        );
    }

    /// Test a file generated by syft.
    ///
    /// Must parse correctly, but doesn't have a PackageURL.
    #[test]
    fn parse_spdx_syft() {
        let data = include_bytes!("../../testdata/syft.spdx.json");
        let sbom = SBOM::parse(data).unwrap();
        assert!(sbom.purl().is_none());
    }

    #[test]
    fn parse_cyclonedx() {
        let data = include_bytes!("../../testdata/my-sbom.json");
        let sbom = SBOM::parse(data).unwrap();
        assert_eq!(
            "pkg:maven/io.seedwing/seedwing-java-example@1.0.0-SNAPSHOT?type=jar",
            sbom.purl().unwrap()
        );
    }

    /// Test a file generated by syft.
    ///
    /// Must parse correctly, but doesn't have a PackageURL.
    #[test]
    fn parse_cyclonedx_syft() {
        tracing_subscriber::fmt().with_max_level(Level::DEBUG).init();

        let data = include_bytes!("../../testdata/syft.cyclonedx.json");
        let sbom = SBOM::parse(data).unwrap();
        assert!(sbom.purl().is_none());
    }
}
