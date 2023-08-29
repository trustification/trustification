use crate::Apply;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchOptions {
    #[serde(default)]
    pub explain: bool,
    #[serde(default)]
    pub metadata: bool,
    #[serde(default = "default_summaries")]
    pub summaries: bool,
}

const fn default_summaries() -> bool {
    true
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            explain: false,
            metadata: false,
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
        } else {
            self = self.query(&[("summaries", "true")]);
        }

        self
    }
}
