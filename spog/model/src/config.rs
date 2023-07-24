use serde::{de::Error, ser::SerializeMap, Deserializer, Serialize, Serializer};
use serde_json::Value;
use url::Url;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Global {
    #[serde(default)]
    pub documentation_url: Option<Url>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LandingPage {
    #[serde(default)]
    pub content: String,
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterCategory {
    pub label: String,
    pub options: Vec<FilterOption>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FilterCheckOption {
    pub id: String,
    pub label: String,
    pub terms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterOption {
    Check(FilterCheckOption),
    Divider,
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
