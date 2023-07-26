use clap::ArgAction;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, clap::Args)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "Authentication")]
pub struct AuthenticatorConfig {
    /// Flag to to disable authentication, default is on.
    #[arg(
        id = "authentication-disabled",
        default_value_t = false,
        long = "authentication-disabled",
        env = "AUTHENTICATION_DISABLED"
    )]
    pub disabled: bool,

    #[command(flatten)]
    pub clients: SingleAuthenticatorClientConfig,
}

/// A structure to configure multiple clients ID in a simple way
#[derive(Clone, Debug, Default, PartialEq, Eq, clap::Args)]
pub struct SingleAuthenticatorClientConfig {
    #[arg(long = "authentication-client-id", action = ArgAction::Append)]
    pub client_ids: Vec<String>,

    #[arg(long = "authentication-issuer-url", required = false)]
    pub issuer_url: String,

    #[arg(default_value_t = false, long = "authentication-tls-insecure")]
    pub tls_insecure: bool,

    #[arg(long = "authentication-tls-certificate", action = ArgAction::Append)]
    pub tls_ca_certificates: Vec<PathBuf>,
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
