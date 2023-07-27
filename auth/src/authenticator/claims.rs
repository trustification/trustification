//! OpenID Connect tools

use super::user::UserDetails;
use openid::{CompactJson, CustomClaims, StandardClaims};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExtendedClaims {
    #[serde(flatten)]
    pub standard_claims: StandardClaims,
    #[serde(flatten)]
    pub extended_claims: serde_json::Value,
}

impl CustomClaims for ExtendedClaims {
    fn standard_claims(&self) -> &StandardClaims {
        &self.standard_claims
    }
}

impl ExtendedClaims {
    fn extract_roles(roles: Option<&Vec<Value>>) -> impl Iterator<Item = String> + '_ {
        roles
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .map(ToString::to_string)
    }

    /// extract roles from claim
    pub fn roles(&self) -> Vec<String> {
        // TODO: This currently on works for Keycloak
        let mut roles = Vec::new();

        // realm access

        let r = &self.extended_claims["realm_access"]["roles"];
        roles.extend(Self::extract_roles(r.as_array()));

        for client in ["services", "drogue"] {
            let r = &self.extended_claims["resource_access"][client]["roles"];
            roles.extend(Self::extract_roles(r.as_array()));
        }

        roles
    }
}

impl CompactJson for ExtendedClaims {}

impl From<ExtendedClaims> for UserDetails {
    fn from(claims: ExtendedClaims) -> Self {
        let roles = claims.roles();
        Self {
            id: claims.standard_claims.sub,
            roles,
        }
    }
}
