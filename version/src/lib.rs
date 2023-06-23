//! A crate to provide version information at runtime, generated during build time.
//!
//! ## Build time
//!
//! During build time it is necessary to have at least the following build script:
//!
//! ```rust
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     trustification_version::build::generate()?;
//!     Ok(())
//! }
//! ```
//!
//! This will ensure all the necessary information is generated. It can then be turned into
//! an information structure like this:
//!
//! ```ignore
//! use trustification_version::version;
//!
//! let version = version!();
//! ```
//!
//! **NOTE**: The macro must be called in the crate the version information should be generated for.
//!
//! ## Runtime
//!
//! Using the macro `version!` will, during runtime, generate a new instance
//! of [`VersionInformation`] containing the information from during the build time. This can
//! be used e.g. in combination with actix:
//!
//! ```ignore
//! use trustification_version::version;
//!
//! actix_web::App::new()
//!    // ...
//!    .configure(version::configurator(version!()));
//! ```
//!
//! Also see: [version::configurator].
//!
//! During runtime it then is possible
#[cfg(feature = "build")]
pub mod build;
#[cfg(feature = "actix-web")]
pub mod version;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct VersionInformation {
    pub name: String,
    pub version: Version,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    #[serde(default, skip_serializing_if = "Git::is_empty")]
    pub git: Git,
    pub build: Build,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Git {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub describe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

impl Git {
    pub fn is_empty(&self) -> bool {
        self.commit.is_none() && self.describe.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Build {
    pub timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Version {
    pub full: String,
    pub major: usize,
    pub minor: usize,
    pub patch: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
}

#[macro_export]
macro_rules! version {
    () => {
        $crate::VersionInformation {
            version: $crate::Version {
                full: env!("CARGO_PKG_VERSION").to_string(),
                major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or_default(),
                minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or_default(),
                patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or_default(),
                pre: option_env!("CARGO_PKG_VERSION_PRE")
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string),
            },

            name: env!("CARGO_PKG_NAME").into(),
            description: env!("CARGO_PKG_DESCRIPTION").into(),

            git: $crate::Git {
                describe: option_env!("VERGEN_GIT_DESCRIBE").map(ToString::to_string),
                commit: option_env!("VERGEN_GIT_SHA").map(ToString::to_string),
            },
            build: $crate::Build {
                timestamp: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
            },
        }
    };
}
