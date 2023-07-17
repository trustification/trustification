use integration_tests::{assert_within_timeout, with_bombastic};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use urlencoding::encode;

#[test]
fn test_upload() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
        let id = "test-upload";
        upload(port, id, &input).await;
        let response = reqwest::get(format!("http://localhost:{port}/api/v1/sbom?id={id}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let output: Value = response.json().await.unwrap();
        assert_eq!(input, output);
    })
}

#[test]
fn test_delete() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
        let id = "test-delete";
        upload(port, id, &input).await;
        let url = &format!("http://localhost:{port}/api/v1/sbom?id={id}");
        let client = reqwest::Client::new();
        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = client.delete(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    })
}

#[test]
fn test_delete_missing() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let client = reqwest::Client::new();
        let response = client
            .delete(format!("http://localhost:{port}/api/v1/sbom"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = client
            .delete(format!("http://localhost:{port}/api/v1/sbom?id="))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = client
            .delete(format!("http://localhost:{port}/api/v1/sbom?id=missing"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    })
}

#[test]
fn test_search() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
        upload(port, "test-search", &input).await;
        assert_within_timeout(Duration::from_secs(30), async move {
            // Ensure we can search for the SBOM. We want to allow the
            // indexer time to do its thing, so might need to retry
            loop {
                let query = encode("ubi9-container-9.1.0-1782.testdata");
                let url = format!("http://localhost:{port}/api/v1/sbom/search?q={query}");
                let response = reqwest::get(url).await.unwrap();
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
}

#[test]
fn test_invalid_type() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let response = reqwest::Client::new()
            .post(format!("http://localhost:{port}/api/v1/sbom?id=foo"))
            .body("<foo/>")
            .header("Content-Type", "application/xml")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get("accept").unwrap(), &"application/json");
    })
}

#[test]
fn test_invalid_encoding() {
    with_bombastic(Duration::from_secs(60), |port| async move {
        let response = reqwest::Client::new()
            .post(format!("http://localhost:{port}/api/v1/sbom?id=foo"))
            .body("{}")
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "braille")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get("accept-encoding").unwrap(), &"bzip2, zstd");
    })
}

async fn upload(port: u16, key: &str, input: &Value) {
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{port}/api/v1/sbom?id={key}"))
        .json(input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}
