use clap::ArgAction;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct AuthenticatorConfig {
    /// Flag to to disable authentication, default is on.
    #[arg(long = "authentication-disabled", env = "AUTHENTICATION_DISABLED")]
    pub disabled: bool,

    #[command(flatten)]
    pub clients: SingleAuthenticatorClientConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthenticatorClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub issuer_url: String,

    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default)]
    pub tls_ca_certificates: Vec<PathBuf>,
}

/// A structure to configure multiple clients ID in a simple way
#[derive(Clone, Debug, PartialEq, Eq, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct SingleAuthenticatorClientConfig {
    #[arg(long = "authenticator-client-id", action = ArgAction::Append)]
    pub client_ids: Vec<String>,

    #[arg(long = "authenticator-issuer-url")]
    pub issuer_url: String,

    #[arg(default_value_t = false, long = "authenticator-tls-insecure")]
    pub tls_insecure: bool,

    #[arg(long = "authenticator-tls-certificate", action = ArgAction::Append)]
    pub tls_ca_certificates: Vec<PathBuf>,
}

impl SingleAuthenticatorClientConfig {
    pub fn expand(self) -> impl Iterator<Item = AuthenticatorClientConfig> {
        self.client_ids
            .into_iter()
            .map(move |client_id| AuthenticatorClientConfig {
                client_id,
                issuer_url: self.issuer_url.clone(),
                tls_ca_certificates: self.tls_ca_certificates.clone(),
                tls_insecure: self.tls_insecure,
            })
    }
}
