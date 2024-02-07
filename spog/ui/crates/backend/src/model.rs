// *NOTE*: Whenever you make changes to this model, re-run `examples/generate_backend_schema.rs`.

use crate::Endpoint;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct OpenIdConnect {
    pub issuer: String,
    #[serde(default = "default::client_id")]
    pub client_id: String,
    #[serde(default = "default::scopes")]
    pub scopes: String,
    #[serde(default = "default::after_logout")]
    pub after_logout: String,
    /// The name of the query parameter receiving the `after_logout` URL
    #[serde(default)]
    pub post_logout_redirect_name: Option<String>,
    /// The URL to navigate to for ending the session
    #[serde(default)]
    pub end_session_url: Option<String>,
}

impl OpenIdConnect {
    pub fn scopes(&self) -> Vec<String> {
        self.scopes.split(' ').map(|s| s.to_string()).collect()
    }
}

mod default {
    pub fn client_id() -> String {
        "frontend".to_string()
    }

    pub fn scopes() -> String {
        "openid".to_string()
    }

    pub fn after_logout() -> String {
        "/notloggedin".to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct Endpoints {
    pub url: Url,
    pub bombastic: Url,
    pub vexination: Url,

    pub oidc: OpenIdConnect,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_write_key: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub external_consent: bool,
}

fn is_default<D: Default + Eq>(value: &D) -> bool {
    D::default() == *value
}

impl Endpoints {
    pub fn get(&self, endpoint: Endpoint) -> &Url {
        match endpoint {
            Endpoint::Api => &self.url,
            Endpoint::Vexination => &self.vexination,
            Endpoint::Bombastic => &self.bombastic,
        }
    }
}
