#![allow(dead_code)]

pub enum SBOM<'a> {
    SPDX(&'a [u8]),
    CycloneDX(&'a [u8]),
}

// TODO: Handle SPDX and use serde instead of raw JSON.
impl<'a> SBOM<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, anyhow::Error> {
        Ok(Self::CycloneDX(data))
    }

    pub fn purl(&self) -> Option<String> {
        match self {
            Self::CycloneDX(data) => {
                let j = serde_json::from_slice::<serde_json::Value>(data).unwrap();
                let purl = j["metadata"]["component"]["purl"].as_str();
                purl.map(|s| s.into())
            }
            Self::SPDX(_) => {
                todo!()
            }
        }
    }
}
