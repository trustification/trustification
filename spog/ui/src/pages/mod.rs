//! Pages in the console

use yew_nested_router::Target;

mod advisory;
mod chicken;
mod index;
mod package;
// mod sbom;
// mod vulnerability;

pub use advisory::*;
pub use chicken::*;
pub use index::*;
// pub use sbom::*;
pub use package::Package;
pub use package::*;
// pub use vulnerability::Vulnerability;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    Chicken,
    Package {
        query: String,
    },
    Advisory {
        query: String,
    },
    /*Vulnerability {
        query: String,
    },*/ //    SBOM,
}
