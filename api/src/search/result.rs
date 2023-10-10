use std::ops::{Deref, DerefMut};

#[derive(utoipa::ToSchema, Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchResult<T> {
    pub result: T,
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

impl<T> From<T> for SearchResult<T> {
    fn from(result: T) -> Self {
        Self { result, total: None }
    }
}
