use integration_tests::{assert_within_timeout, run_test};
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[test]
fn test_bombastic() {
    run_test(Duration::from_secs(60), async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
        upload("ubi9", &input).await;
        assert_eq!(fetch("ubi9").await, input);
        search().await;
        upload_invalid_type().await;
        upload_invalid_encoding().await;
        Ok(())
    })
}

async fn upload(key: &str, input: &Value) {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://localhost:8082/api/v1/sbom?id={key}"))
        .json(input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn fetch(key: &str) -> Value {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://localhost:8082/api/v1/sbom?id={key}"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

async fn search() {
    assert_within_timeout(Duration::from_secs(30), async move {
        let client = reqwest::Client::new();
        // Ensure we can search for the SBOM. We want to allow the
        // indexer time to do its thing, so might need to retry
        loop {
            let response = client
                .get("http://localhost:8082/api/v1/sbom/search?q=")
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let response: Value = response.json().await.unwrap();
            if let Some(Some(1)) = response.get("total").map(|t| t.as_i64()) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
}

async fn upload_invalid_type() {
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:8082/api/v1/sbom?id=foo")
        .body("<foo/>")
        .header("Content-Type", "application/xml")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("accept").unwrap(), &"application/json");
}

async fn upload_invalid_encoding() {
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:8082/api/v1/sbom?id=foo")
        .body("{}")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "braille")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers().get("accept-encoding").unwrap(), &"bzip2, zstd");
}
