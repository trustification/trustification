#![allow(dead_code)]

pub enum SBOM<'a> {
    SPDX { raw: &'a [u8], purl: Option<String> },
    CycloneDX { raw: &'a [u8], purl: Option<String> },
}

// TODO:
// * Use serde instead of raw JSON to avoid copying
// * Or let seedwing handle it
impl<'a> SBOM<'a> {
    pub fn raw(&self) -> &[u8] {
        match self {
            Self::SPDX { raw, purl: _ } => raw,
            Self::CycloneDX { raw, purl: _ } => raw,
        }
    }
    pub fn parse(data: &'a [u8]) -> Result<Self, anyhow::Error> {
        let j = serde_json::from_slice::<serde_json::Value>(data)?;

        if j.get("SPDXID").is_some() {
            let mut purl = None;
            if let Some(Some(Some(describes))) = j.get("documentDescribes").map(|o| o.as_array()).map(|o| {
                if let Some(o) = o {
                    o.first().map(|s| s.as_str())
                } else {
                    None
                }
            }) {
                if let Some(Some(packages)) = j.get("packages").map(|o| o.as_array()) {
                    let mut package = None;
                    for p in packages.iter() {
                        if let Some(Some(id)) = p.get("SPDXID").map(|s| s.as_str()) {
                            if id == describes {
                                package.replace(p);
                                break;
                            }
                        }
                    }

                    if let Some(package) = package {
                        if let Some(Some(refs)) = package.get("externalRefs").map(|o| o.as_array()) {
                            for r in refs.iter() {
                                match (
                                    r.get("referenceType").map(|v| v.as_str()),
                                    r.get("referenceLocator").map(|v| v.as_str()),
                                ) {
                                    (Some(Some(rtype)), Some(Some(loc))) => {
                                        if rtype == "purl" {
                                            purl.replace(loc.to_string());
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            // Traverse doc to find entry
            // TODO: Better way to do this...
            //

            return Ok(Self::SPDX { raw: data, purl });
        }

        if j.get("bomFormat").is_some() {
            if let Some(metadata) = j.get("metadata") {
                if let Some(component) = metadata.get("component") {
                    if let Some(Some(purl)) = component.get("purl").map(|s| s.as_str()) {
                        return Ok(Self::CycloneDX {
                            raw: data,
                            purl: Some(purl.into()),
                        });
                    } else {
                        return Ok(Self::CycloneDX { raw: data, purl: None });
                    }
                }
            }
            return Err(anyhow::anyhow!("Error finding purl"));
        }
        Err(anyhow::anyhow!("Unknown format"))
    }

    pub fn purl(&self) -> Option<String> {
        match self {
            Self::CycloneDX { raw: _, purl } => purl.clone(),
            Self::SPDX { raw: _, purl } => purl.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SBOM;

    #[test]
    fn parse_spdx() {
        let data = include_bytes!("../../testdata/my-sbom.json");
        let sbom = SBOM::parse(data).unwrap();
        assert_eq!(
            "pkg:maven/io.seedwing/seedwing-java-example@1.0.0-SNAPSHOT?type=jar",
            sbom.purl().unwrap()
        );
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
}
