use utoipa::ToSchema;

/// The action triggered by a suggestion
#[derive(Clone, Debug, PartialEq, Eq, ToSchema, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Cve(String),
}

/// A search suggestion for auto-completion
#[derive(Clone, Debug, PartialEq, Eq, ToSchema, serde::Serialize, serde::Deserialize)]
pub struct Suggestion {
    /// the main label
    pub label: String,
    /// a more descriptive text
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// the action to perform when selected
    pub action: Action,
}
