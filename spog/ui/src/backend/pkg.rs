use super::{Backend, Error};
use crate::backend::data::{Package, PackageDependencies, PackageDependents, PackageList, PackageRef};
use crate::backend::Endpoint;
use packageurl::PackageUrl;
use serde::Deserialize;

pub struct PackageService {
    backend: Backend,
    client: reqwest::Client,
}

#[allow(unused)]
impl PackageService {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            client: reqwest::Client::new(),
        }
    }

    pub async fn lookup(&self, purl: PackageUrl<'_>) -> Result<Package, Error> {
        Ok(self
            .client
            .get(self.backend.join(Endpoint::Api, "/api/package")?)
            .query(&[("purl", purl.to_string())])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn lookup_batch<'a, I>(&self, purls: I) -> Result<Vec<PackageRef>, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
    {
        self.batch_to_refs("/api/package", purls).await
    }

    pub async fn dependencies<'a, I>(&self, purls: I) -> Result<Vec<PackageDependencies>, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
    {
        self.batch_to_refs("/api/package/dependencies", purls).await
    }

    pub async fn dependents<'a, I>(&self, purls: I) -> Result<Vec<PackageDependents>, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
    {
        self.batch_to_refs("/api/package/dependents", purls).await
    }

    pub async fn search<'a, I>(&self, purls: I) -> Result<PackageDependents, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
    {
        self.batch_to_refs("/api/package/search", purls).await
    }

    /// common call of getting some refs for a batch of purls
    async fn batch_to_refs<'a, I, R>(&self, path: &str, purls: I) -> Result<R, Error>
    where
        I: IntoIterator<Item = PackageUrl<'a>>,
        for<'de> R: Deserialize<'de>,
    {
        let purls = PackageList(purls.into_iter().map(|purl| purl.to_string()).collect::<Vec<_>>());

        Ok(self
            .client
            .post(self.backend.join(Endpoint::Api, path)?)
            .json(&purls)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
