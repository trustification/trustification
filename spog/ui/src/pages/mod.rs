//! Pages in the console

use yew_nested_router::Target;

mod advisory;
mod chicken;
mod index;
mod not_found;
mod not_logged_in;
mod package;
mod sbom;
mod scanner;
mod search;
mod vex;

pub use advisory::*;
pub use chicken::*;
pub use index::*;
pub use not_found::*;
pub use not_logged_in::*;
pub use package::Package;
pub use sbom::*;
pub use scanner::*;
pub use search::*;
pub use vex::*;

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
