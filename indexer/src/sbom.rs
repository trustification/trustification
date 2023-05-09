#![allow(dead_code)]

pub enum SBOM<'a> {
    SPDX {
        raw: &'a [u8],
        // TODO: Purl
    },
    CycloneDX {
        raw: &'a [u8],
        purl: Option<String>,
    },
}

// TODO:
// * Use serde instead of raw JSON to avoid copying
// * Or let seedwing handle it
impl<'a> SBOM<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, anyhow::Error> {
        let j = serde_json::from_slice::<serde_json::Value>(data)?;

        if j.get("SPDXID").is_some() {
            return Ok(Self::SPDX { raw: data });
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
            Self::SPDX { raw: _ } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SBOM;

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
