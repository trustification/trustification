mod access_token;
mod openid;

pub use self::access_token::*;
pub use self::openid::*;

use super::error::Error;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum Credentials {
    Bearer(String),
    Basic(String, Option<String>),
}

/// A provider for access credentials (mostly access tokens).
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error>;
}

#[async_trait]
impl<T> TokenProvider for Arc<T>
where
    T: TokenProvider,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

#[async_trait]
impl<T> TokenProvider for &Arc<T>
where
    T: TokenProvider,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

#[async_trait]
impl TokenProvider for Arc<dyn TokenProvider> {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

/// A token provider which does not provide tokens.
#[derive(Debug, Clone, Copy)]
pub struct NoTokenProvider;

#[async_trait]
impl TokenProvider for NoTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(None)
    }
}

#[async_trait]
impl<T> TokenProvider for Option<T>
where
    T: TokenProvider + Sync,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        match self {
            None => Ok(None),
            Some(provider) => provider.provide_access_token().await,
        }
    }
}

#[async_trait]
impl TokenProvider for String {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Bearer(self.clone())))
    }
}

#[cfg(feature = "actix")]
#[async_trait]
impl TokenProvider for BearerAuth {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Bearer(self.token().to_string())))
    }
}
