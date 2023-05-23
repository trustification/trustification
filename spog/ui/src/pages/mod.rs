//! Pages in the console

use yew_nested_router::Target;

mod chicken;
mod index;
mod package;
mod sbom;
mod vulnerability;

pub use chicken::*;
pub use index::*;
pub use package::*;
pub use sbom::*;
pub use vulnerability::*;

#[derive(Clone, Debug, PartialEq, Eq, Target)]
pub enum AppRoute {
    #[target(index)]
    Index,
    Chicken,
    Package {
        package: String,
    },
    Vulnerability {
        cve: String,
    },
    SBOM,
}
