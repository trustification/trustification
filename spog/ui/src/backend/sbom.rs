use std::rc::Rc;
use url::Url;

use super::{Backend, Error};
use crate::backend::Endpoint;

#[allow(unused)]
pub struct SBOMService {
    backend: Rc<Backend>,
    client: reqwest::Client,
}

#[allow(unused)]
impl SBOMService {
    pub fn new(backend: Rc<Backend>) -> Self {
        Self {
            backend,
            client: reqwest::Client::new(),
        }
    }

    pub fn download_href(&self, pkg: impl AsRef<str>) -> Result<Url, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/package/sbom")?;

        url.query_pairs_mut().append_pair("purl", pkg.as_ref()).finish();

        Ok(url)
    }

    pub async fn get(&self, id: impl AsRef<str>) -> Result<String, Error> {
        let mut url = self.backend.join(Endpoint::Api, "/api/v1/package")?;
        url.query_pairs_mut().append_pair("id", id.as_ref()).finish();

        Ok(self.client.get(url).send().await?.error_for_status()?.text().await?)
    }
}
