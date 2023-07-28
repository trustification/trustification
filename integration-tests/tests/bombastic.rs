use integration_tests::{assert_within_timeout, with_bombastic, with_test_context, TestingContext};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[tokio::test]
async fn test_upload() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
            let id = "test-upload";
            upload(port, id, &input, &context).await;
            let response = reqwest::Client::new()
                .get(format!("http://localhost:{port}/api/v1/sbom?id={id}"))
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let output: Value = response.json().await.unwrap();
            assert_eq!(input, output);
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_delete() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
            let id = "test-delete";
            upload(port, id, &input, &context).await;
            let url = &format!("http://localhost:{port}/api/v1/sbom?id={id}");
            let client = reqwest::Client::new();
            let response = client
                .get(url)
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response = client
                .delete(url)
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            let response = client
                .get(url)
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_delete_missing() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let client = reqwest::Client::new();
            let response = client
                .delete(format!("http://localhost:{port}/api/v1/sbom"))
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let response = client
                .delete(format!("http://localhost:{port}/api/v1/sbom?id="))
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            let response = client
                .delete(format!("http://localhost:{port}/api/v1/sbom?id=missing"))
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_search() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
            upload(port, "test-search", &input, &context).await;
            assert_within_timeout(Duration::from_secs(30), async move {
                // Ensure we can search for the SBOM. We want to allow the
                // indexer time to do its thing, so might need to retry
                loop {
                    let query = encode("ubi9-container-9.1.0-1782.testdata");
                    let url = format!("http://localhost:{port}/api/v1/sbom/search?q={query}");
                    let response = reqwest::Client::new()
                        .get(url)
                        .inject_token(&context.provider_manager)
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
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_invalid_type() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let response = reqwest::Client::new()
                .post(format!("http://localhost:{port}/api/v1/sbom?id=foo"))
                .body("<foo/>")
                .header("Content-Type", "application/xml")
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers().get("accept").unwrap(), &"application/json");
        })
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_invalid_encoding() {
    with_test_context(|context| async move {
        with_bombastic(context, Duration::from_secs(60), |context, port| async move {
            let response = reqwest::Client::new()
                .post(format!("http://localhost:{port}/api/v1/sbom?id=foo"))
                .body("{}")
                .header("Content-Type", "application/json")
                .header("Content-Encoding", "braille")
                .inject_token(&context.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers().get("accept-encoding").unwrap(), &"bzip2, zstd");
        })
        .await;
    })
    .await;
}

async fn upload(port: u16, key: &str, input: &Value, context: &TestingContext) {
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
