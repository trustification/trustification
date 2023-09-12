use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cvss31Data {
    pub base_score: f32,
    pub vector_string: String,
}
