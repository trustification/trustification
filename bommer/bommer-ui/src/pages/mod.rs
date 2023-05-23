//! Pages in the console

use yew_nested_router::Target;

mod index;
mod workload;

pub use index::*;
pub use workload::*;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    ByNamespace {
        namespace: String,
    },
}
