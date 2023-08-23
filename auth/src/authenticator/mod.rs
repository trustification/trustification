//! Server side authentication (verification)

mod claims;
mod default;
mod validate;

pub use default::*;

#[cfg(feature = "actix")]
pub mod actix;
pub mod config;
pub mod error;
pub mod user;

use crate::{authenticator::claims::ValidatedAccessToken, authenticator::config::AuthenticatorConfig};
use biscuit::jws::Compact;
use claims::AccessTokenClaims;
use config::AuthenticatorClientConfig;
use error::AuthenticationError;
use futures_util::{stream, StreamExt, TryStreamExt};
use openid::{Client, Configurable, Discovered, Empty, Jws};
use std::collections::HashMap;
use std::ops::Deref;
use tracing::instrument;
use trustification_common::reqwest::ClientFactory;

/// An authenticator to authenticate incoming requests.
#[derive(Clone)]
pub struct Authenticator {
    pub clients: Vec<AuthenticatorClient>,
}

impl Authenticator {
    fn from_clients(clients: Vec<AuthenticatorClient>) -> Self {
        Self { clients }
    }

    pub async fn from_config(config: Option<AuthenticatorConfig>) -> anyhow::Result<Option<Self>> {
        let config = match config {
            Some(config) => config,
            None => return Ok(None),
        };

        Ok(Some(Self::from_configs(config.clients).await?))
    }

    pub async fn from_configs<I>(configs: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = AuthenticatorClientConfig>,
    {
        let clients = stream::iter(configs)
            .map(Ok)
            .and_then(|config| async move { create_client(config).await })
            .try_collect()
            .await?;

        Ok(Self::from_clients(clients))
    }

    fn find_client(
        &self,
        token: &Compact<AccessTokenClaims, Empty>,
    ) -> Result<Option<&AuthenticatorClient>, AuthenticationError> {
        let unverified_payload = token.unverified_payload().map_err(|err| {
            log::info!("Failed to decode token payload: {}", err);
            AuthenticationError::Failed
        })?;

        let client_id = &unverified_payload.azp;

        log::debug!("Searching client for: {} / {:?}", unverified_payload.iss, client_id);

        // find the client to use

        let client = self.clients.iter().find(|client| {
            let provider_iss = &client.provider.config().issuer;
            let provider_id = &client.client_id;

            log::debug!("Checking client: {} / {}", provider_iss, provider_id);
            if provider_iss != &unverified_payload.iss {
                return false;
            }
            if let Some(client_id) = client_id {
                if client_id != provider_id {
                    return false;
                }
            }

            true
        });

        Ok(client)
    }

    /// Validate a bearer token.
    #[instrument(level = "debug", skip_all, fields(token=token.as_ref()), ret)]
    pub async fn validate_token<S: AsRef<str>>(&self, token: S) -> Result<ValidatedAccessToken, AuthenticationError> {
        let mut token: Compact<AccessTokenClaims, Empty> = Jws::new_encoded(token.as_ref());

        let client = self.find_client(&token)?.ok_or_else(|| {
            log::debug!("Unable to find client");
            AuthenticationError::Failed
        })?;

        log::debug!("Using client: {}", client.client_id);

        client.decode_token(&mut token).map_err(|err| {
            log::debug!("Failed to decode token: {}", err);
            AuthenticationError::Failed
        })?;

        log::debug!("Token: {:?}", token);

        validate::validate_token(client, &token, client.audience.as_deref(), None).map_err(|err| {
            log::debug!("Validation failed: {}", err);
            AuthenticationError::Failed
        })?;

        match token {
            Compact::Decoded { payload, .. } => Ok(client.convert_token(payload)),
            Compact::Encoded(_) => Err(AuthenticationError::Failed),
        }
    }
}

async fn create_client(config: AuthenticatorClientConfig) -> anyhow::Result<AuthenticatorClient> {
    let mut client = ClientFactory::new();

    if config.tls_insecure {
        client = client.make_insecure();
    }

    for ca in config.tls_ca_certificates {
        client = client.add_ca_cert(ca);
    }

    let client = Client::<Discovered>::discover_with_client(
        client.build()?,
        config.client_id,
        None,
        None,
        config.issuer_url.parse()?,
    )
    .await?;

    log::debug!("Discovered OpenID: {:#?}", client.config());

    Ok(AuthenticatorClient {
        client,
        audience: config.required_audience,
        scope_mappings: config.scope_mappings,
    })
}

#[derive(Clone)]
pub struct AuthenticatorClient {
    client: Client<Discovered>,
    audience: Option<String>,
    scope_mappings: HashMap<String, Vec<String>>,
}

impl AuthenticatorClient {
    /// Convert from a set of (verified!) access token claims into a [`ValidatedAccessToken`] struct.
    pub fn convert_token(&self, access_token: AccessTokenClaims) -> ValidatedAccessToken {
        let mapped_scopes = Self::map_scopes(&access_token.scope, &self.scope_mappings);
        ValidatedAccessToken {
            access_token,
            mapped_scopes,
        }
    }

    fn map_scopes(scopes: &str, scope_mappings: &HashMap<String, Vec<String>>) -> Vec<String> {
        scopes
            .split(' ')
            .flat_map(|scope| {
                scope_mappings
                    .get(scope)
                    .cloned()
                    .unwrap_or_else(|| vec![scope.to_string()])
            })
            .collect()
    }
}

impl Deref for AuthenticatorClient {
    type Target = Client<Discovered>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn assert_scope_mapping(scopes: &str, mappings: &[(&str, &[&str])], expected: &[&str]) {
        let mappings = mappings
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|v| v.to_string()).collect()))
            .collect::<HashMap<String, Vec<String>>>();
        let expected = expected.iter().map(|item| item.to_string()).collect::<Vec<_>>();
        let result = AuthenticatorClient::map_scopes(scopes, &mappings);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scope_mapping() {
        assert_scope_mapping(
            "foo bar baz",
            &[("foo", &["read:foo", "read:bar"] as &[_]), ("baz", &[])],
            &["read:foo", "read:bar", "bar"],
        );
    }

    #[test]
    fn test_no_scope_mapping() {
        assert_scope_mapping("foo bar baz", &[], &["foo", "bar", "baz"]);
    }
}
