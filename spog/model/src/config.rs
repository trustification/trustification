use url::Url;

// *NOTE*: Whenever you make changes to this model, re-run `examples/generate_spog_schema.rs`.

/// SPoG UI configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    #[serde(default)]
    pub global: Global,
    #[serde(default)]
    pub landing_page: LandingPage,
    #[serde(default)]
    pub bombastic: Bombastic,
    #[serde(default)]
    pub vexination: Vexination,
    #[serde(default)]
    pub cve: Cve,
    #[serde(default)]
    pub scanner: Scanner,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub consent: Consent,
    #[serde(default)]
    pub packages: Packages,
}

/// Configuration for the consent dialog
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Consent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_yes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_no: Option<String>,
}

/// Features for SPoG UI which can enabled/disabled.
///
/// By default, all features are enabled.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    /// Enables the SBOM scanner
    #[serde(default = "default_feature")]
    pub scanner: bool,
    /// Enables the "extend" section
    #[serde(default = "default_feature")]
    pub extend_section: bool,
    /// Enable the dedicated search views (including the "complex" mode).
    #[serde(default = "default_feature")]
    pub dedicated_search: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            extend_section: default_feature(),
            scanner: default_feature(),
            dedicated_search: default_feature(),
        }
    }
}

const fn default_feature() -> bool {
    true
}

/// Global values which affect the overall console
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Global {
    #[serde(default)]
    pub documentation_url: Option<Url>,

    #[serde(default)]
    pub support_url: Option<Url>,

    #[serde(default)]
    pub support_case_url: Option<Url>,

    #[serde(default)]
    pub brand_image_src: Option<String>,

    #[serde(default)]
    pub about_background_src: Option<String>,

    #[serde(default)]
    pub product_name: Option<String>,
}

pub const DEFAULT_BRAND_SRC: &str = "assets/brand/trustification_logo_hori_reverse.svg";
pub const DEFAULT_ABOUT_BACKGROUND_SRC: &str = "assets/images/pfbg-icon.svg";
pub const DEFAULT_PRODUCT_NAME: &str = "Chicken Coop";

impl Global {
    pub fn brand_image_src(&self) -> String {
        self.brand_image_src.as_deref().unwrap_or(DEFAULT_BRAND_SRC).to_string()
    }

    pub fn about_background_src(&self) -> String {
        self.about_background_src
            .as_deref()
            .unwrap_or(DEFAULT_ABOUT_BACKGROUND_SRC)
            .to_string()
    }

    pub fn product_name(&self) -> String {
        self.product_name.as_deref().unwrap_or(DEFAULT_PRODUCT_NAME).to_string()
    }
}

/// Configuration for the landing page
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LandingPage {
    /// Content above the search entry box section
    #[serde(default)]
    pub header_content: String,

    /// Content directly before the entry box
    #[serde(default)]
    pub before_outer_content: String,

    /// Content directly before the entry box
    #[serde(default)]
    pub before_inner_content: String,

    /// Content directly after the entry box
    #[serde(default)]
    pub after_inner_content: String,

    /// Content directly after the entry box
    #[serde(default)]
    pub after_outer_content: String,

    /// Content below the search entry box section
    #[serde(default)]
    pub footer_content: String,
}

/// Scanner specific configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Scanner {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Adding a link to a blog post explaining how to create an SBOM
    pub documentation_url: Option<Url>,
    /// The welcome hint section. If `None`, then no hint is shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_hint: Option<Hint>,
}

/// A hint configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Hint {
    /// The title to show. Must be valid HTML.
    pub title: String,
    /// The body content of the hint. Must be valid HTML.
    pub body: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Packages {
    #[serde(default)]
    pub filters: Filters,
}
/// Bombastic specific configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Bombastic {
    #[serde(default)]
    pub filters: Filters,
}

/// Vexination specific configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Vexination {
    #[serde(default)]
    pub filters: Filters,
}

/// CVE specific configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    #[serde(default)]
    pub filters: Filters,
}

/// A set of customizable filters
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Filters {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<FilterCategory>,
}

/// A filter category
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterCategory {
    pub label: String,
    pub options: Vec<FilterOption>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Terms {
    /// A list of search terms
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terms: Vec<String>,
    /// A JavaScript snippet to execute, gathering search terms.
    ///
    /// The result must be an array of strings. For example:
    ///
    /// ```yaml
    /// script: |
    ///   ["foo:bar", "bar:baz"]
    /// ```
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub script: String,
}

/// Values for a filter option
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterCheckOption {
    /// Internal ID (must be unique)
    pub id: String,
    /// End-user friendly label
    pub label: String,

    /// Search terms which will be added using an OR group
    #[serde(flatten)]
    pub terms: Terms,
}

/// Select style choice (one of)
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterSelectOption {
    /// Internal ID (groups radio options)
    pub group: String,
    /// The ID of the option which should be selected by default
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Search terms which will be added using an OR group
    pub options: Vec<FilterSelectItem>,
}

/// Item of a [`FilterSelectOption`]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterSelectItem {
    /// Internal ID (must be unique for a radio group)
    pub id: String,
    /// End-user friendly label
    pub label: String,

    /// Search terms which will be added using an OR group
    #[serde(flatten)]
    pub terms: Terms,
}

/// The filter option element which can be added
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum FilterOption {
    /// Add a checkbox option
    Check(FilterCheckOption),
    /// Add a select/radio button
    Select(FilterSelectOption),
    /// Add a visual divider
    Divider,
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn mock_check_option(id: impl Into<String>, label: impl Into<String>) -> FilterCheckOption {
        FilterCheckOption {
            id: id.into(),
            label: label.into(),
            terms: Terms::default(),
        }
    }

    fn mock_check(id: impl Into<String>, label: impl Into<String>) -> FilterOption {
        FilterOption::Check(mock_check_option(id, label))
    }

    fn mock_select(
        group: impl Into<String>,
        options: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> FilterOption {
        FilterOption::Select(FilterSelectOption {
            group: group.into(),
            default: None,
            options: options
                .into_iter()
                .map(|(id, label)| FilterSelectItem {
                    id: id.into(),
                    label: label.into(),
                    terms: Terms::default(),
                })
                .collect(),
        })
    }

    #[test]
    fn test_deserialize_options_1() {
        assert_eq!(
            serde_json::from_value::<Vec<FilterOption>>(json!([
                {
                    "type": "check",
                    "id": "id1",
                    "label": "label1",
                    "terms": [],
                }
            ]))
            .unwrap(),
            vec![mock_check("id1", "label1")],
        )
    }

    #[test]
    fn test_deserialize_options_2() {
        assert_eq!(
            serde_json::from_value::<Vec<FilterOption>>(json!([
                {
                    "type": "check",
                    "id": "id1",
                    "label": "label1",
                    "terms": [],
                },
                { "type": "divider" },
                {
                    "type": "check",
                    "id": "id2",
                    "label": "label2",
                    "terms": [],
                },
            ]))
            .unwrap(),
            vec![
                mock_check("id1", "label1"),
                FilterOption::Divider,
                mock_check("id2", "label2")
            ],
        )
    }

    /// ensure that re-encoding the content keeps it equal
    #[test]
    fn test_ensure_eq() {
        let options = serde_json::from_value::<Vec<FilterOption>>(json!([
            {
                "type": "check",
                "id": "id1",
                "label": "label1",
                "terms": [],
            },
            { "type": "divider" },
            {
                "type": "check",
                "id": "id2",
                "label": "label2",
                "terms": [],
            },
            {
                "type": "select",
                "group": "id3",
                "options": [
                    { "id": "a", "label": "A", "terms": [] },
                    { "id": "b", "label": "B", "terms": [] },
                    { "id": "c", "label": "C", "terms": [] },
                ],
            },
        ]))
        .unwrap();

        let f = Filters {
            categories: vec![FilterCategory {
                label: "cat1".to_string(),
                options,
            }],
        };

        let f: Filters = serde_json::from_value(serde_json::to_value(f).unwrap()).unwrap();

        assert_eq!(
            f,
            Filters {
                categories: vec![FilterCategory {
                    label: "cat1".to_string(),
                    options: vec![
                        mock_check("id1", "label1"),
                        FilterOption::Divider,
                        mock_check("id2", "label2"),
                        mock_select("id3", [("a", "A"), ("b", "B"), ("c", "C")])
                    ]
                }]
            }
        )
    }
}
