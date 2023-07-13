//! Pages in the console

use yew_nested_router::Target;

mod advisory;
mod chicken;
mod index;
mod not_found;
mod package;
mod sbom;
mod vex;

pub use advisory::*;
pub use chicken::*;
pub use index::*;
pub use not_found::*;
pub use package::Package;
pub use sbom::*;
pub use vex::*;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    Chicken,
    Package(View),
    Advisory(View),
}

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum View {
    Search { query: String },
    Content { id: String },
}

impl Default for View {
    fn default() -> Self {
        Self::Search {
            query: Default::default(),
        }
    }
}
