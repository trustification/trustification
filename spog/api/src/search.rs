use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
pub struct QueryParams {
    /// The query string
    #[serde(default)]
    pub q: String,
    /// Offset to start from returning results.
    #[serde(default = "default_offset")]
    pub offset: usize,
    /// Maximum number of results to return
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    100
}
