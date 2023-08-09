//! Server side authentication (verification)

mod claims;
mod validate;

#[cfg(feature = "actix")]
pub mod actix;
pub mod config;
pub mod error;
pub mod user;

use claims::ExtendedClaims;
use config::{AuthenticatorClientConfig, AuthenticatorConfig};
use error::AuthenticationError;
use futures_util::{stream, StreamExt, TryStreamExt};
use openid::{biscuit::jws::Compact, Claims, Client, CompactJson, Configurable, Discovered, Empty, Jws};
use std::ops::Deref;
use tracing::instrument;
use trustification_common::reqwest::ClientFactory;

/// An authenticator to authenticate incoming requests.
#[derive(Clone)]
pub struct Authenticator {
    pub clients: Vec<AuthenticatorClient<ExtendedClaims>>,
}

impl Authenticator {
    fn from_clients(clients: Vec<AuthenticatorClient<ExtendedClaims>>) -> Self {
        Self { clients }
    }

    pub async fn from_devmode_or_config(devmode: bool, config: AuthenticatorConfig) -> anyhow::Result<Option<Self>> {
        match devmode {
            true => Self::from_config(AuthenticatorConfig::devmode()).await,
            false => Self::from_config(config).await,
        }
    }

    pub async fn from_config(config: AuthenticatorConfig) -> anyhow::Result<Option<Self>> {
        if config.disabled {
            return Ok(None);
        }

        Ok(Some(Self::from_configs(config.clients.expand()).await?))
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
        token: &Compact<ExtendedClaims, Empty>,
    ) -> Result<Option<&AuthenticatorClient<ExtendedClaims>>, AuthenticationError> {
        let unverified_payload = token.unverified_payload().map_err(|err| {
            log::info!("Failed to decode token payload: {}", err);
            AuthenticationError::Failed
        })?;

        let client_id = unverified_payload.standard_claims.azp.as_ref();

        log::debug!(
            "Searching client for: {} / {:?}",
            unverified_payload.standard_claims.iss,
            client_id
        );

        // find the client to use

        let client = self.clients.iter().find(|client| {
            let provider_iss = &client.provider.config().issuer;
            let provider_id = &client.client_id;

            log::debug!("Checking client: {} / {}", provider_iss, provider_id);
            if provider_iss != &unverified_payload.standard_claims.iss {
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
    pub async fn validate_token<S: AsRef<str>>(&self, token: S) -> Result<ExtendedClaims, AuthenticationError> {
        let mut token: Compact<ExtendedClaims, Empty> = Jws::new_encoded(token.as_ref());

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
            Compact::Decoded { payload, .. } => Ok(payload),
            Compact::Encoded(_) => Err(AuthenticationError::Failed),
        }
    }
}

async fn create_client<P: CompactJson + Claims>(
    config: AuthenticatorClientConfig,
) -> anyhow::Result<AuthenticatorClient<P>> {
    let mut client = ClientFactory::new();

    if config.tls_insecure {
        client = client.make_insecure();
    }

    for ca in config.tls_ca_certificates {
        client = client.add_ca_cert(ca);
    }

    let client = Client::<Discovered, P>::discover_with_client(
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
    })
}

#[derive(Clone)]
pub struct AuthenticatorClient<P>
where
    P: CompactJson + Claims,
{
    client: Client<Discovered, P>,
    audience: Option<String>,
}

impl<P> Deref for AuthenticatorClient<P>
where
    P: CompactJson + Claims,
{
    type Target = Client<Discovered, P>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
