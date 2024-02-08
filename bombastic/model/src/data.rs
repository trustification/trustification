use std::fmt::Formatter;
use tracing::{info_span, instrument};

pub enum SBOM {
    #[cfg(feature = "cyclonedx-bom")]
    CycloneDX(cyclonedx_bom::prelude::Bom),
    #[cfg(feature = "spdx-rs")]
    SPDX(spdx_rs::models::SPDX),
}

#[derive(Debug, Default)]
pub struct Error {
    #[cfg(feature = "cyclonedx-bom")]
    cyclonedx: Option<cyclonedx_bom::errors::JsonReadError>,
    #[cfg(feature = "spdx-rs")]
    spdx: Option<serde_json::Error>,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error parsing SBOM (")?;
        let mut first = true;
        #[cfg(feature = "cyclonedx-bom")]
        {
            if let Some(err) = &self.cyclonedx {
                write!(f, "CycloneDX: {}", err)?;
                first = false;
            }
        }
        #[cfg(feature = "spdx-rs")]
        {
            if let Some(err) = &self.spdx {
                if !first {
                    write!(f, ", ")?;
                }
                write!(f, "SPDX: {}", err)?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl std::error::Error for Error {}

impl SBOM {
    #[instrument(skip_all, fields(data_len={data.len()}), err)]
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let mut err: Error = Default::default();

        #[cfg(feature = "spdx-rs")]
        {
            let result = info_span!("parse spdx").in_scope(|| serde_json::from_slice::<spdx_rs::models::SPDX>(data));
            match result.map_err(|e| {
                log::info!("Error parsing SPDX: {:?}", e);
                e
            }) {
                Ok(spdx) => return Ok(SBOM::SPDX(spdx)),
                Err(e) => {
                    err.spdx = Some(e);
                }
            }
        }

        #[cfg(feature = "cyclonedx-bom")]
        {
            let result = info_span!("parse cyclonedx").in_scope(|| cyclonedx_bom::prelude::Bom::parse_from_json(data));
            match result.map_err(|e| {
                log::info!("Error parsing CycloneDX: {:?}", e);
                e
            }) {
                Ok(bom) => return Ok(SBOM::CycloneDX(bom)),
                Err(e) => {
                    err.cyclonedx = Some(e);
                }
            }
        }

        Err(err)
    }

    pub fn type_str(&self) -> String {
        match self {
            #[cfg(feature = "spdx-rs")]
            Self::SPDX(sbom) => format!("SPDX/{}", sbom.document_creation_information.spdx_version),
            #[cfg(feature = "cyclonedx-bom")]
            Self::CycloneDX(_) => "CycloneDX/1.3".to_string(),
        }
    }
}
