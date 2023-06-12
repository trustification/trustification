use url::Url;

use super::{Backend, Error};
use crate::backend::Endpoint;

#[allow(unused)]
pub struct SBOMService {
    backend: Backend,
}

#[allow(unused)]
impl SBOMService {
    pub fn new(backend: Backend) -> Self {
        Self { backend }
    }

    pub fn download_href(&self, pkg: impl AsRef<str>) -> Result<Url, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/package/sbom")?;

        url.query_pairs_mut().append_pair("purl", pkg.as_ref()).finish();

        Ok(url)
    }
}
