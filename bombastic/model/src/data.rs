use std::fmt::Formatter;

pub enum SBOM {
    #[cfg(feature = "cyclonedx-bom")]
    CycloneDX(cyclonedx_bom::prelude::Bom),
    #[cfg(feature = "spdx-rs")]
    SPDX(spdx_rs::models::SPDX),
}

#[derive(Debug)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error parsing SBOM")
    }
}

impl std::error::Error for Error {}

impl SBOM {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        #[cfg(feature = "spdx-rsp")]
        if let Ok(bom) = serde_json::from_slice::<spdx_rs::models::SPDX>(data).map_err(|e| {
            log::info!("Error parsing SPDX: {:?}", e);
            e
        }) {
            return Ok(SBOM::SPDX(spdx));
        }

        #[cfg(feature = "cyclonedx-bom")]
        if let Ok(bom) = cyclonedx_bom::prelude::Bom::parse_from_json_v1_3(data).map_err(|e| {
            log::info!("Error parsing CycloneDX: {:?}", e);
            e
        }) {
            return Ok(SBOM::CycloneDX(bom));
        }

        Err(Error)
    }
}
