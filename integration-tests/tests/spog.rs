use std::time::Duration;

use integration_tests::{assert_within_timeout, upload_sbom, upload_vex, SpogContext};
use reqwest::StatusCode;
use serde_json::{json, Value};
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

    // Check forwarding of search errors
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "http://localhost:{port}/api/v1/package/search",
            port = context.port
        ))
        .query(&[("q", urlencoding::encode("unknown:field"))])
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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

/// SPoG API might enrich results from package search with related vulnerabilities. This test checks that this
/// is working as expected for the test data.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_search_correlation(context: &mut SpogContext) {
    let input = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    upload_sbom(context.bombastic.port, "stf-1.5", &input, &context.bombastic.provider).await;

    let input = serde_json::from_str(include_str!("testdata/correlation/rhsa-2023_1529.json")).unwrap();
    upload_vex(context.vexination.port, &input, &context.vexination.provider).await;

    let client = reqwest::Client::new();

    assert_within_timeout(Duration::from_secs(30), async move {
        // Ensure we can search for the data. We want to allow the
        // indexer time to do its thing, so might need to retry
        loop {
            let response = client
                .get(format!(
                    "http://localhost:{port}/api/v1/package/search?q=package%3Astf-1.5",
                    port = context.port
                ))
                .inject_token(&context.provider.provider_user)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = response.json().await.unwrap();
            if payload["total"].as_u64().unwrap() >= 1 {
                assert_eq!(payload["result"][0]["name"], json!("stf-1.5"));

                let data: spog_model::search::PackageSummary =
                    serde_json::from_value(payload["result"][0].clone()).unwrap();
                // println!("Data: {:?}", data);
                // Data might not be available until vex index is synced
                if data.advisories.len() >= 1 {
                    assert_eq!(data.advisories[0], "RHSA-2023:1529");
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await;
}
