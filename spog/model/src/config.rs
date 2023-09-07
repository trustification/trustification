use schemars::schema::InstanceType;
use schemars::{
    gen::SchemaGenerator,
    schema::{ObjectValidation, Schema, SchemaObject, SubschemaValidation},
    JsonSchema,
};
use serde::{de::Error, ser::SerializeMap, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use url::Url;

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
    pub scanner: Scanner,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub consent: Consent,
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
    pub brand_image_src: Option<String>,

    #[serde(default)]
    pub about_background_src: Option<String>,

    #[serde(default)]
    pub product_name: Option<String>,
}

pub const DEFAULT_BRAND_SRC: &str = "assets/images/chicken-svgrepo-com.svg";
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
    /// The title to show
    pub title: String,
    /// The body content of the hint. Must be valid HTML.
    pub body: String,
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

/// Values for a filter option
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterCheckOption {
    /// Internal ID (must be unique)
    pub id: String,
    /// End-user friendly label
    pub label: String,
    /// Search terms which will be added using an OR group
    pub terms: Vec<String>,
}

/// The filter option element which can be added
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterOption {
    /// Add a checkbox option
    Check(FilterCheckOption),
    /// Add a visual divider
    Divider,
}

impl JsonSchema for FilterOption {
    fn schema_name() -> String {
        "FilterOption".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        // divider

        let divider = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(ObjectValidation {
                additional_properties: Some(Box::new(false.into())),
                properties: [("divider".to_string(), {
                    let mut schema: SchemaObject = <bool>::json_schema(gen).into();
                    schema.const_value = Some(json!(true));
                    schema.into()
                })]
                .into_iter()
                .collect(),
                ..Default::default()
            })),
            ..SchemaObject::default()
        };

        // check option

        let check_option = gen.subschema_for::<FilterCheckOption>();

        // one-of

        let schema = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(vec![check_option, divider.into()]),
                ..Default::default()
            })),
            ..Default::default()
        };

        // return

        schema.into()
    }
}

impl Serialize for FilterOption {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FilterOption::Divider => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("divider", &true)?;
                map.end()
            }

            FilterOption::Check(opt) => opt.serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for FilterOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer)?;
        if let Some(divider) = value.get("divider").and_then(|v| v.as_bool()) {
            match divider {
                true => Ok(FilterOption::Divider),
                false => Err(Error::custom("the field 'divider' must have a value of 'true'")),
            }
        } else {
            Ok(FilterOption::Check(
                FilterCheckOption::deserialize(value).map_err(Error::custom)?,
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn mock_check_option(id: impl Into<String>, label: impl Into<String>) -> FilterCheckOption {
        FilterCheckOption {
            id: id.into(),
            label: label.into(),
            terms: vec![],
        }
    }

    fn mock_check(id: impl Into<String>, label: impl Into<String>) -> FilterOption {
        FilterOption::Check(mock_check_option(id, label))
    }

    #[test]
    fn test_deserialize_options_1() {
        assert_eq!(
            serde_json::from_value::<Vec<FilterOption>>(json!([
                {
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
                    "id": "id1",
                    "label": "label1",
                    "terms": [],
                },
                { "divider": true },
                {
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

    #[test]
    fn test_deserialize_options_3() {
        assert!(serde_json::from_value::<Vec<FilterOption>>(json!([
            {
                "id": "id1",
                "label": "label1",
                "terms": [],
            },
            { "divider": false }, // error
            {
                "id": "id2",
                "label": "label2",
                "terms": [],
            },
        ]))
        .is_err(),)
    }

    /// ensure that re-encoding the content keeps it equal
    #[test]
    fn test_ensure_eq() {
        let options = serde_json::from_value::<Vec<FilterOption>>(json!([
            {
                "id": "id1",
                "label": "label1",
                "terms": [],
            },
            { "divider": true },
            {
                "id": "id2",
                "label": "label2",
                "terms": [],
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
                        mock_check("id2", "label2")
                    ]
                }]
            }
        )
    }
}
