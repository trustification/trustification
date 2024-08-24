use std::fmt::Formatter;

use cyclonedx_bom::errors::JsonReadError;
use cyclonedx_bom::prelude::{Validate, ValidationResult};
use tracing::{info_span, instrument};

#[derive(Debug)]
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
            match result {
                Ok(spdx) => return Ok(SBOM::SPDX(spdx)),
                Err(e) => {
                    log::error!("Error parsing SPDX: {:?}", e);
                    err.spdx = Some(e);
                }
            }
        }

        #[cfg(feature = "cyclonedx-bom")]
        {
            let result = info_span!("parse cyclonedx").in_scope(|| cyclonedx_bom::prelude::Bom::parse_from_json(data));
            match result {
                // check the serial number has a value
                Ok(bom) => match bom.serial_number {
                    // then validate the SBOM itself
                    // having checked the serial number is available before validating is mandatory
                    // because it's an optional field in specs and the validation will succeed if
                    // the serial number is missing and this isn't what we want because
                    // serial number is mandatory for trustification to correlate properly
                    Some(_) => match bom.validate() {
                        Ok(validation_result) => match validation_result {
                            ValidationResult::Passed => return Ok(SBOM::CycloneDX(bom)),
                            ValidationResult::Failed { reasons } => {
                                let all_reasons = reasons
                                    .into_iter()
                                    .map(|reason| reason.message)
                                    .collect::<Vec<String>>()
                                    .join(", ");
                                log::error!("Error validating CycloneDX: {}", all_reasons);
                                let validation_failed: serde_json::Error = serde::de::Error::custom(all_reasons);
                                err.cyclonedx = Some(JsonReadError::from(validation_failed));
                            }
                        },
                        Err(e) => {
                            log::error!("Error validating CycloneDX: {}", e);
                            let validation_error: serde_json::Error = serde::de::Error::custom(e);
                            err.cyclonedx = Some(JsonReadError::from(validation_error));
                        }
                    },
                    None => {
                        let serial_number_error_message = "Error validating CycloneDX: In order for a CycloneDX SBOM to be successfully ingested the 'serialNumber' field must be populated.";
                        log::error!("{}", serial_number_error_message);
                        let serial_number_error: serde_json::Error =
                            serde::de::Error::custom(serial_number_error_message);
                        err.cyclonedx = Some(JsonReadError::from(serial_number_error));
                    }
                },
                Err(e) => {
                    log::error!("Error parsing CycloneDX: {:?}", e);
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

#[cfg(test)]
mod tests {
    use super::SBOM;

    #[test]
    fn parse_cyclonedx_valid_13() {
        let data = include_bytes!("../../testdata/my-sbom.json");
        let result = SBOM::parse(data);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_cyclonedx_valid_14() {
        let data = include_bytes!("../../testdata/syft.cyclonedx.json");
        let result = SBOM::parse(data);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_cyclonedx_invalid_serial_number() {
        let data = include_bytes!("../../testdata/syft.cyclonedx.wrong-serialNumber.json");
        let result = SBOM::parse(data);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert!(e.cyclonedx.is_some());
        assert_eq!(
            e.cyclonedx.unwrap().to_string(),
            "Failed to deserialize JSON: UrnUuid does not match regular expression"
        );
    }

    #[test]
    fn parse_cyclonedx_without_serial_number() {
        let data = include_bytes!("../../testdata/sbom-without-serialNumber.cyclonedx.json");
        let e = SBOM::parse(data).unwrap_err();
        assert!(e.cyclonedx.is_some());
        assert_eq!(e.cyclonedx.unwrap().to_string(), "Failed to deserialize JSON: Error validating CycloneDX: In order for a CycloneDX SBOM to be successfully ingested the 'serialNumber' field must be populated.");
        assert!(e.spdx.is_some());
        assert_eq!(
            e.spdx.unwrap().to_string(),
            "missing field `spdxVersion` at line 454 column 1"
        );
    }
}
