use std::ops::{Deref, DerefMut};

/// A way to use comma seperated values in a config structure.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(from = "String")]
pub struct CommaSeparatedVec(pub Vec<String>);

impl Deref for CommaSeparatedVec {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CommaSeparatedVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<String>> for CommaSeparatedVec {
    fn from(values: Vec<String>) -> Self {
        Self(values)
    }
}

impl From<String> for CommaSeparatedVec {
    fn from(value: String) -> Self {
        Self(value.split(',').map(|s| s.into()).collect::<Vec<String>>())
    }
}
