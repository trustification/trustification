use std::sync::Arc;
use trustification_auth::client::{OpenIdTokenProvider, TokenProvider};
use trustification_auth::devmode;

#[derive(Clone)]
pub struct ProviderContext {
    pub provider_user: Arc<dyn TokenProvider>,
    pub provider_manager: Arc<dyn TokenProvider>,
}

pub async fn create_provider_context() -> ProviderContext {
    ProviderContext {
        provider_user: create_provider("testing-user", devmode::SSO_CLIENT_SECRET, devmode::issuer_url()).await,
        provider_manager: create_provider("testing-manager", devmode::SSO_CLIENT_SECRET, devmode::issuer_url()).await,
    }
}

pub async fn create_provider(client_id: &str, secret: &str, issuer: impl AsRef<str>) -> Arc<OpenIdTokenProvider> {
    let client_user = openid::Client::discover(
        client_id.into(),
        Some(secret.to_string()),
        None,
        issuer.as_ref().parse().unwrap(),
    )
    .await
    .unwrap();

    let provider = trustification_auth::client::OpenIdTokenProvider::new(client_user, chrono::Duration::seconds(10));

    Arc::new(provider)
}
