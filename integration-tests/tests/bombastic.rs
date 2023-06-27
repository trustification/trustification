use integration_tests::{assert_within_timeout, run_test};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;

#[test]
fn test_upload() {
    run_test(Duration::from_secs(60), |port, _| async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
        let id = "ubi9";
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
fn test_search() {
    run_test(Duration::from_secs(60), |port, _| async move {
        let input = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
        let key = "ubi9";
        upload(port, key, &input).await;
        assert_within_timeout(Duration::from_secs(30), async move {
            // Ensure we can search for the SBOM. We want to allow the
            // indexer time to do its thing, so might need to retry
            loop {
                let url = format!("http://localhost:{port}/api/v1/sbom/search?q={key}");
                let response = reqwest::get(url).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let payload: Value = response.json().await.unwrap();
                if payload["total"] == json!(1) {
                    assert_eq!(
                        payload["result"][0]["document"]["version"],
                        json!("ubi9-container-9.1.0-1782.noarch")
                    );
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
    run_test(Duration::from_secs(60), |port, _| async move {
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
    run_test(Duration::from_secs(60), |port, _| async move {
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
