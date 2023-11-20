pub mod data;
pub mod packages;
pub mod search;

pub mod prelude {
    pub use crate::data::*;
    pub use crate::packages::*;
    pub use crate::search::*;
}
