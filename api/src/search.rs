use crate::Apply;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchOptions {
    #[serde(default)]
    pub explain: bool,
    #[serde(default)]
    pub metadata: bool,
    #[serde(default)]
    pub summaries: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            explain: Default::default(),
            metadata: Default::default(),
            summaries: true,
        }
    }
}

impl Apply<SearchOptions> for reqwest::RequestBuilder {
    fn apply(mut self, options: &SearchOptions) -> Self {
        if options.explain {
            self = self.query(&[("explain", "true")]);
        }

        if options.metadata {
            self = self.query(&[("metadata", "true")]);
        }

        if !options.summaries {
            self = self.query(&[("summaries", "false")]);
        }

        self
    }
}
