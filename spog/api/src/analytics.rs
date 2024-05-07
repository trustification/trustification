use serde_json::Value;
use trustification_analytics::TrackingEvent;

#[derive(Copy, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomType {
    CycloneDx,
    Spdx,
}

/// Event when the user scans an SBOM
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ScanSbom {
    pub r#type: SbomType,
    /// status code in the case of an error
    pub status_code: Option<u16>,
}

impl TrackingEvent for ScanSbom {
    fn name(&self) -> &str {
        "scan_sbom"
    }

    fn payload(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}
