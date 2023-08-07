//! Pages in the console

use yew_nested_router::Target;

mod advisory;
mod advisory_search;
mod chicken;
mod index;
mod not_found;
mod not_logged_in;
mod sbom;
mod sbom_search;
mod scanner;
mod search;

pub use advisory::*;
pub use advisory_search::*;
pub use chicken::*;
pub use index::*;
pub use not_found::*;
pub use not_logged_in::*;
pub use sbom::*;
pub use sbom_search::Package;
pub use scanner::*;
pub use search::Search;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    NotLoggedIn,
    Chicken,
    Package(View),
    Advisory(View),
    Scanner,
    Search {
        terms: String,
    },
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
