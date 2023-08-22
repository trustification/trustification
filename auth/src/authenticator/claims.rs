//! OpenID Connect tools

use super::user::UserDetails;
use biscuit::SingleOrMultiple;
use openid::CompactJson;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    #[serde(default)]
    pub azp: Option<String>,
    pub sub: String,
    pub iss: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<SingleOrMultiple<String>>,

    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub auth_time: Option<i64>,

    #[serde(flatten)]
    pub extended_claims: Value,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

impl CompactJson for AccessTokenClaims {}

impl From<AccessTokenClaims> for UserDetails {
    fn from(claims: AccessTokenClaims) -> Self {
        let scopes = claims.scope.split(' ').map(ToString::to_string).collect();
        Self {
            id: claims.sub,
            scopes,
            roles: Default::default(),
        }
    }
}
