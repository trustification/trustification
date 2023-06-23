//! Pages in the console

use yew_nested_router::Target;

mod advisory;
mod catalog;
mod chicken;
mod index;
mod package;
mod sbom;
// mod vulnerability;

pub use advisory::*;
pub use catalog::*;
pub use chicken::*;
pub use index::*;
pub use package::Package;
pub use package::*;
pub use sbom::*;
// pub use vulnerability::Vulnerability;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    Chicken,
    Package {
        query: String,
    },
    Catalog {
        query: String,
    },
    SBOM {
        id: String,
    },
    Advisory {
        query: String,
    },
    /*Vulnerability {
        query: String,
    },*/
}
