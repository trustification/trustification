use super::{super::error::Error, Credentials, TokenProvider};
use async_trait::async_trait;
use std::fmt::{Debug, Formatter};

/// A token provider, using user access tokens (not OAuth2 access tokens).
///
/// If you want to directly use an OAuth2 access token, you can pass the access token as a String,
/// as `TokenProvider` is implemented for `String`. Also see: [token providers]
///
/// [token providers]: TokenProvider#implementors
#[derive(Clone)]
pub struct AccessTokenProvider {
    pub user: String,
    pub token: String,
}

impl Debug for AccessTokenProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenProvider")
            .field("user", &self.user)
            .field("token", &"***")
            .finish()
    }
}

#[async_trait]
impl TokenProvider for AccessTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Basic(self.user.clone(), Some(self.token.clone()))))
    }
}
