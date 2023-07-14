#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Configuration {
    #[serde(default)]
    pub bombastic: Bombastic,
    #[serde(default)]
    pub vexination: Vexination,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Bombastic {
    #[serde(default)]
    pub filters: Filters,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Vexination {
    #[serde(default)]
    pub filters: Filters,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Filters {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<FilterCategory>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterCategory {
    pub label: String,
    pub options: Vec<FilterOption>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterOption {
    pub id: String,
    pub label: String,
    pub terms: Vec<String>,
}
