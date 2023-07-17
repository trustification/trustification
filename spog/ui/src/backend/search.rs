use reqwest::RequestBuilder;
use trustification_api::{search::SearchOptions, Apply};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchParameters {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub options: SearchOptions,
}

impl Default for SearchParameters {
    fn default() -> Self {
        Self {
            offset: None,
            limit: None,
            options: SearchOptions {
                // in debug mode, we ask for metadata by default
                metadata: default_metadata(),
                ..Default::default()
            },
        }
    }
}

#[cfg(not(debug_assertions))]
const fn default_metadata() -> bool {
    false
}

#[cfg(debug_assertions)]
const fn default_metadata() -> bool {
    true
}

impl Apply<SearchParameters> for RequestBuilder {
    fn apply(mut self, value: &SearchParameters) -> Self {
        if let Some(limit) = value.limit {
            self = self.query(&[("limit", limit)]);
        }

        if let Some(offset) = value.offset {
            self = self.query(&[("offset", offset)]);
        }

        self = self.apply(&value.options);

        self
    }
}
