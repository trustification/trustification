use std::ops::{Deref, DerefMut};

pub use vexination_model::prelude::ProductPackage;

#[derive(serde::Deserialize, serde::Serialize, Debug, PartialEq, Clone)]
pub struct VulnSummary {
    pub cve: String,
    pub title: String,
    pub release: time::OffsetDateTime,
    pub description: String,
    pub cvss: f64,
    pub affected: Vec<ProductPackage>,
    pub fixed: Vec<ProductPackage>,
    pub advisories: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchResult<T> {
    pub result: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

impl<T> SearchResult<T> {
    pub fn map<F, U>(self, f: F) -> SearchResult<U>
    where
        F: FnOnce(T) -> U,
    {
        SearchResult {
            result: f(self.result),
            total: self.total,
        }
    }
}

impl<T> Deref for SearchResult<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

impl<T> DerefMut for SearchResult<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.result
    }
}

impl<T> From<(T, usize)> for SearchResult<T> {
    fn from((result, total): (T, usize)) -> Self {
        Self {
            result,
            total: Some(total),
        }
    }
}
