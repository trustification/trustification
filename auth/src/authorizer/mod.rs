use crate::authenticator::{error::AuthorizationError, user::UserDetails};

pub enum Permission {}

#[derive(Debug, Clone, Copy)]
pub enum Authorizer {
    Enabled,
    Disabled,
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::Enabled
    }
}

impl Authorizer {
    pub fn require_scope(&self, user: Option<UserDetails>, scope: impl AsRef<str>) -> Result<(), AuthorizationError> {
        match self {
            Self::Enabled => {
                if let Some(user) = user {
                    user.require_scope(scope)
                } else {
                    Err(AuthorizationError::Failed)
                }
            }
            Self::Disabled => {
                log::warn!("WARNING: Authorization disabled, all permissions granted");
                Ok(())
            }
        }
    }
}
