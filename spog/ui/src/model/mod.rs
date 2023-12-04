use std::rc::Rc;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
pub enum SBOM {
    CycloneDX {
        bom: Rc<cyclonedx_bom::prelude::Bom>,
        source: Rc<String>,
    },
    #[allow(clippy::upper_case_acronyms)]
    SPDX {
        bom: Rc<spdx_rs::models::SPDX>,
        source: Rc<String>,
    },
    Unknown(Rc<String>),
}

impl SBOM {
    pub fn parse(source: String) -> Self {
        let source = Rc::new(source);
        if let Ok(bom) = cyclonedx_bom::prelude::Bom::parse_from_json_v1_3(source.as_bytes()) {
            SBOM::CycloneDX {
                bom: Rc::new(bom),
                source,
            }
        } else if let Ok(bom) = serde_json::from_str::<spdx_rs::models::SPDX>(&source) {
            SBOM::SPDX {
                bom: Rc::new(bom),
                source,
            }
        } else {
            SBOM::Unknown(source)
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::CycloneDX { .. } => "CycloneDX",
            Self::SPDX { .. } => "SPDX",
            Self::Unknown(_) => "Unknown",
        }
    }

    pub fn get_source(&self) -> Rc<String> {
        match self {
            Self::CycloneDX { source, .. } => source.clone(),
            Self::SPDX { source, .. } => source.clone(),
            Self::Unknown(source) => source.clone(),
        }
    }
}
