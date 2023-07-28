use super::{SSO_ENDPOINT, SSO_TESTING_CLIENT_SECRET};
use std::sync::Arc;
use trustification_auth::client::{OpenIdTokenProvider, TokenProvider};

#[derive(Clone)]
pub struct ProviderContext {
    pub provider_user: Arc<dyn TokenProvider>,
    pub provider_manager: Arc<dyn TokenProvider>,
}

pub async fn create_provider_context() -> ProviderContext {
    ProviderContext {
        provider_user: create_provider("testing-user").await,
        provider_manager: create_provider("testing-manager").await,
    }
}

async fn create_provider(client_id: &str) -> Arc<OpenIdTokenProvider> {
    let client_user = openid::Client::discover(
        client_id.into(),
        Some(SSO_TESTING_CLIENT_SECRET.to_string()),
        None,
        SSO_ENDPOINT.parse().unwrap(),
    )
    .await
    .unwrap();

    let provider = trustification_auth::client::OpenIdTokenProvider::new(client_user, chrono::Duration::seconds(10));

    println!("Initial access token: {:?}", provider.provide_access_token().await);

    Arc::new(provider)
}
