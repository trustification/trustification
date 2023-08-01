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
    assert_eq!(response.status(), StatusCode::OK);
    let version: Value = response.json().await.unwrap();
    assert_eq!(version["name"], "spog-api");
}

/// SPoG is the entrypoint for the frontend. It exposes a search API, but forwards requests
/// to bombastic of vexination. This requires forwarding the token too. This test is here to
/// test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn test_search_forward_bombastic(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "http://localhost:{port}/api/v1/package/search",
            port = context.port
        ))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let data: Value = response.json().await.unwrap();
    println!("{data:#?}");
}

/// SPoG is the entrypoint for the frontend. It exposes a search API, but forwards requests
/// to bombastic of vexination. This requires forwarding the token too. This test is here to
/// test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn test_search_forward_vexination(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "http://localhost:{port}/api/v1/advisory/search",
            port = context.port
        ))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let data: Value = response.json().await.unwrap();
    println!("{data:#?}");
}

#[test_with::env(CRDA_URL)]
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_crda_integration(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let sbom = include_bytes!("crda/test1.sbom.json");

    let response = client
        .post(format!(
            "http://localhost:{port}/api/v1/analyze/report",
            port = context.port
        ))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .body(sbom.as_slice())
        .send()
        .await
        .unwrap();

    let status = response.status();
    println!("Response: {}", status);
    let html = response.text().await;
    println!("{html:#?}");

    assert_eq!(status, StatusCode::OK);
}
