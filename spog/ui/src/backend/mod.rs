// pub mod data;

pub mod data {
    pub use spog_model::prelude::*;
}

mod pkg;
mod sbom;
mod vuln;

pub use pkg::*;
pub use sbom::*;
pub use vuln::*;

use url::{ParseError, Url};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub endpoints: Endpoints,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Endpoints {
    pub api_url: Url,
    pub search_url: Url,
}

impl Endpoints {
    pub fn get(&self, endpoint: Endpoint) -> &Url {
        match endpoint {
            Endpoint::Api => &self.api_url,
            Endpoint::Search => &self.search_url,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Endpoint {
    Api,
    Search,
}

impl Backend {
    pub fn join(&self, endpoint: Endpoint, input: &str) -> Result<Url, Error> {
        Ok(self.endpoints.get(endpoint).join(input)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
}
