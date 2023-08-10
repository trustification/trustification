pub mod authenticator;
pub mod authorizer;
pub mod client;
pub mod devmode;

#[cfg(feature = "swagger")]
pub mod swagger_ui;

/// A registered user
pub const ROLE_USER: &str = "chicken-user";
/// A registered user, allowed to manage content (write)
pub const ROLE_MANAGER: &str = "chicken-manager";
/// A registered user, allowed to perform all operations
pub const ROLE_ADMIN: &str = "chicken-admin";
