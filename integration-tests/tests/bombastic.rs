use integration_tests::{assert_within_timeout, BombasticContext, ProviderContext};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload";
    upload(context.port, id, &input, &context.provider).await;
    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{port}/api/v1/sbom?id={id}",
            port = context.port
        ))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let output: Value = response.json().await.unwrap();
    assert_eq!(input, output);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete";
    upload(context.port, id, &input, &context.provider).await;
    let url = &format!("http://localhost:{port}/api/v1/sbom?id={id}", port = context.port);
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .delete(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .get(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete_missing(context: &mut BombasticContext) {
    let client = reqwest::Client::new();
    let response = client
        .delete(format!("http://localhost:{port}/api/v1/sbom", port = context.port))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = client
        .delete(format!("http://localhost:{port}/api/v1/sbom?id=", port = context.port))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .delete(format!(
            "http://localhost:{port}/api/v1/sbom?id=missing",
            port = context.port
        ))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_search(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    upload(context.port, "test-search", &input, &context.provider).await;
    assert_within_timeout(Duration::from_secs(30), async move {
        // Ensure we can search for the SBOM. We want to allow the
        // indexer time to do its thing, so might need to retry
        loop {
            let query = encode("ubi9-container-9.1.0-1782.testdata");
            let url = format!(
                "http://localhost:{port}/api/v1/sbom/search?q={query}",
                port = context.port
            );
            let response = reqwest::Client::new()
                .get(url)
                .inject_token(&context.provider.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = response.json().await.unwrap();
            if payload["total"].as_u64().unwrap() >= 1 {
                assert_eq!(payload["result"][0]["document"]["name"], json!("ubi9-container"));
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_invalid_type(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{port}/api/v1/sbom?id=foo",
            port = context.port
        ))
        .body("<foo/>")
        .header("Content-Type", "application/xml")
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("accept").unwrap(), &"application/json");
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_invalid_encoding(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{port}/api/v1/sbom?id=foo",
            port = context.port
        ))
        .body("{}")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "braille")
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("accept-encoding").unwrap(), &"bzip2, zstd");
}

async fn upload(port: u16, key: &str, input: &Value, context: &ProviderContext) {
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .json(input)
        .inject_token(&context.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}
