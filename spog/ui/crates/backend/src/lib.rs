pub mod data {
    pub use spog_model::prelude::*;
}

mod access_token;
mod advisory;
mod analyze;
mod config;
mod cve;
mod dashboard;
mod hooks;
mod model;
mod package_info;
mod pkg;
mod sbom;
mod search;
mod suggestion;
mod version;

pub use self::cve::*;
pub use access_token::*;
pub use advisory::*;
pub use analyze::*;
pub use config::*;
pub use dashboard::*;
pub use hooks::*;
pub use model::*;
pub use package_info::*;
pub use pkg::*;
pub use sbom::*;
pub use search::*;
pub use suggestion::*;
pub use version::*;

use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub endpoints: Endpoints,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Endpoint {
    Api,
    Vexination,
    Bombastic,
}

impl Backend {
    pub fn join(&self, endpoint: Endpoint, input: &str) -> Result<Url, url::ParseError> {
        self.endpoints.get(endpoint).join(input)
    }
}
