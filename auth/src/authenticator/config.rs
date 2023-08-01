use clap::ArgAction;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, clap::Args)]
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

impl AuthenticatorConfig {
    /// Create "devmode" configuration
    pub fn devmode() -> Self {
        AuthenticatorConfig {
            disabled: false,
            clients: SingleAuthenticatorClientConfig {
                client_ids: vec!["frontend".to_string()],
                issuer_url: std::env::var("ISSUER_URL")
                    .unwrap_or_else(|_| "http://localhost:8090/realms/chicken".to_string()),
                ..Default::default()
            },
        }
    }
}

/// A structure to configure multiple clients ID in a simple way
#[derive(Clone, Debug, Default, PartialEq, Eq, clap::Args)]
pub struct SingleAuthenticatorClientConfig {
    /// The clients IDs to allow
    #[arg(env = "AUTHENTICATOR_OIDC_CLIENT_IDS", long = "authentication-client-id", action = ArgAction::Append)]
    pub client_ids: Vec<String>,

    /// The issuer URL of the clients.
    #[arg(
        env = "AUTHENTICATOR_OIDC_ISSUER_URL",
        long = "authentication-issuer-url",
        default_value = "",
        required = false
    )]
    pub issuer_url: String,

    /// Enforce an "audience" to he present in the access token
    #[arg(
        env = "AUTHENTICATOR_OIDC_REQUIRED_AUDIENCE",
        long = "authentication-required-audience"
    )]
    pub required_audience: Option<String>,

    /// Allow insecure TLS connections with the SSO server (this is insecure!)
    #[arg(
        env = "AUTHENTICATOR_OIDC_TLS_INSECURE",
        default_value_t = false,
        long = "authentication-tls-insecure"
    )]
    pub tls_insecure: bool,

    /// Enable additional TLS certificates for communication with the SSO server
    #[arg(env= "AUTHENTICATOR_OIDC_TLS_CA_CERTIFICATES", long = "authentication-tls-certificate", action = ArgAction::Append)]
    pub tls_ca_certificates: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthenticatorClientConfig {
    pub client_id: String,

    #[serde(default)]
    pub issuer_url: String,
    #[serde(default)]
    pub required_audience: Option<String>,

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
                required_audience: self.required_audience.clone(),
            })
    }
}
