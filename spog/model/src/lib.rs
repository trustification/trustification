pub mod config;
pub mod csaf;
pub mod cve;
pub mod dashboard;
pub mod package_info;
pub mod pkg;
pub mod search;
pub mod suggestion;
pub mod vuln;

pub mod prelude {
    pub use crate::{config::*, cve::*, dashboard::*, package_info::*, pkg::*, search::*, suggestion::*, vuln::*};
}
