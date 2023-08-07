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
            _ => None,
        }
    }
}
