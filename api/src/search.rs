use crate::Apply;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SearchOptions {
    #[serde(default)]
    pub explain: bool,
    #[serde(default)]
    pub metadata: bool,
}

impl Apply<SearchOptions> for reqwest::RequestBuilder {
    fn apply(mut self, options: &SearchOptions) -> Self {
        if options.explain {
            self = self.query(&[("explain", "true")]);
        }

        if options.metadata {
            self = self.query(&[("metadata", "true")]);
        }

        self
    }
}
