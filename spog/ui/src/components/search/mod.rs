mod dynamic;
mod help;
mod simple;
mod toolbar;

pub use dynamic::*;
pub use help::*;
pub use simple::*;
pub use toolbar::*;

#[derive(Clone, PartialEq, Eq)]
pub enum SearchPropertiesMode {
    Managed { query: Option<String> },
    Provided { terms: String },
}

impl SearchPropertiesMode {
    pub fn props_query(&self) -> Option<String> {
        match &self {
            Self::Managed { query } => query.clone(),
            Self::Provided { terms } => Some(terms.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prop_query() {
        let mode = SearchPropertiesMode::Managed {
            query: Some("some_managed".to_string()),
        };
        assert_eq!(mode.props_query(), Some("some_managed".to_string()));

        let mode = SearchPropertiesMode::Provided {
            terms: "some_term".to_string(),
        };
        assert_eq!(mode.props_query(), Some("some_term".to_string()));
    }
}
