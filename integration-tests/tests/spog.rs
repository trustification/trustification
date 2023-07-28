use integration_tests::{with_spog, with_test_context};
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;
use trustification_auth::client::TokenInjector;

#[tokio::test]
async fn test_version() {
    with_test_context(|context| async move {
        with_spog(context, Duration::from_secs(30), |context, port| async move {
            let response = reqwest::Client::new()
                .get(format!("http://localhost:{port}/.well-known/trustification/version"))
                .inject_token(&context.provider)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            // let response = reqwest::get().inject_token(provider).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let version: Value = response.json().await.unwrap();
            assert_eq!(version["name"], "spog-api");
        })
        .await;
    })
    .await;
}
