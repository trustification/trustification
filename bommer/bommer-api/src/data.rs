use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub pods: HashSet<PodRef>,
    pub sbom: SbomState,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SbomState {
    Scheduled,
    Err(String),
    Missing,
    Found(SBOM),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SBOM {
    pub data: String,
}

/// A reference to a pod
#[derive(
    Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct PodRef {
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageState {
    pub pods: HashSet<PodRef>,
}

#[derive(
    Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Deserialize, serde::Serialize,
)]
pub struct ImageRef(pub String);

impl Display for ImageRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Deref for ImageRef {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Event<K, V>
where
    K: Clone + Debug + Eq + Hash,
    V: Clone + Debug,
{
    Added(K, V),
    Modified(K, V),
    Removed(K),
    Restart(HashMap<K, V>),
}
