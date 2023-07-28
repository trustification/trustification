use integration_tests::SpogContext;
use reqwest::StatusCode;
use serde_json::Value;
use test_context::test_context;
use trustification_auth::client::TokenInjector;

#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn test_version(context: &mut SpogContext) {
    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{port}/.well-known/trustification/version",
            port = context.port
        ))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    // let response = reqwest::get().inject_token(provider).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let version: Value = response.json().await.unwrap();
    assert_eq!(version["name"], "spog-api");
}
