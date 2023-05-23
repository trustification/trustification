use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use bommer_api::data::{Image, ImageRef};

use super::{Backend, Error};

pub struct WorkloadService {
    backend: Backend,
    client: reqwest::Client,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Workload(pub HashMap<ImageRef, Image>);

impl Deref for Workload {
    type Target = HashMap<ImageRef, Image>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Workload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[allow(unused)]
impl WorkloadService {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            client: reqwest::Client::new(),
        }
    }

    pub async fn lookup(&self) -> Result<Workload, Error> {
        Ok(self
            .client
            .get(self.backend.join("/api/v1/workload")?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
