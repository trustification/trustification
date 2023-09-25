use std::time::Duration;

use integration_tests::{delete_sbom, delete_vex, upload_sbom, upload_vex, SpogContext, Urlifier};
use reqwest::StatusCode;
use serde_json::{json, Value};
use test_context::test_context;
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn spog_version(context: &mut SpogContext) {
    let response = reqwest::Client::new()
        .get(context.urlify("/.well-known/trustification/version"))
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
async fn spog_search_forward_bombastic(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let response = client
        .get(context.urlify("/api/v1/package/search"))
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
        .get(context.urlify("/api/v1/package/search"))
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
async fn spog_search_forward_vexination(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let response = client
        .get(context.urlify("/api/v1/advisory/search"))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[test_with::env(CRDA_URL)]
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn spog_crda_integration(context: &mut SpogContext) {
    let client = reqwest::Client::new();

    let sbom = include_bytes!("crda/test1.sbom.json");

    let response = client
        .post(context.urlify("/api/v1/analyze/report"))
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
#[ntest::timeout(120_000)]
async fn spog_search_correlation(context: &mut SpogContext) {
    let input = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let sbom_id = "test-stf-1.5";
    upload_sbom(&context.bombastic, sbom_id, &input).await;

    let input = serde_json::from_str(include_str!("testdata/correlation/rhsa-2023_1529.json")).unwrap();
    upload_vex(&context.vexination, &input).await;
    let vex_id = input["document"]["tracking"]["id"].as_str().unwrap();

    let client = reqwest::Client::new();

    // Ensure we can search for the data. We want to allow the
    // indexer time to do its thing, so might need to retry
    loop {
        let response = client
            .get(context.urlify("/api/v1/package/search?q=package%3Astf-1.5"))
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
            // we need to have some information
            assert!(data.advisories.is_some());
            // Data might not be available until vex index is synced
            let advisories = data.advisories.unwrap();
            if advisories > 0 {
                assert_eq!(advisories, 1);
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    delete_sbom(&context.bombastic, sbom_id).await;
    delete_vex(&context.vexination, &encode(vex_id)).await;
}

/// SPoG is the entrypoint for the frontend. It exposes an dependencies API, but forwards requests
/// to Guac. This test is here to test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn spog_dependencies(context: &mut SpogContext) {
    let input = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let sbom_id = "test-stf-1.5";
    upload_sbom(&context.bombastic, sbom_id, &input).await;

    let client = reqwest::Client::new();

    let purl: &str = "pkg:rpm/redhat/json-c@0.13.1-0.4.el8";

    let mut attempt = 1;
    loop {
        let response = client
            .get(context.urlify("/api/v1/packages"))
            .query(&[("purl", purl)])
            .inject_token(&context.provider.provider_user)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let payload: Value = response.json().await.unwrap();
        let pkgs = payload.as_array().unwrap();
        if pkgs.contains(&json!({"purl": "pkg:rpm/json-c@0.13.1-0.4.el8?arch=x86_64"})) {
            break;
        }

        attempt += 1;
        assert!(attempt < 10, "Guac ingestion failed, no packages available");
        // wait a bit until the SBOM gets ingested into Guac
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let response = client
        .get(context.urlify("/api/v1/packages/dependents"))
        .query(&[("purl", purl)])
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value = response.json().await.unwrap();
    let deps = payload.as_array().unwrap();
    assert!(deps.contains(&json!({"purl": "pkg:oci/sg-core@sha256:fae8586bc4872450e0f01f99a6202deec63ebd6b2ea8eb5c3f280229fa176da2?tag=5.1.1-3"})));

    let purl: &str = "pkg:rpm/redhat/python-zope-event@4.2.0-9.2.el8stf";
    let response = client
        .get(context.urlify("/api/v1/packages/dependencies"))
        .query(&[("purl", purl)])
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload: Value = response.json().await.unwrap();
    let deps = payload.as_array().unwrap();
    assert!(deps.contains(&json!({"purl": "pkg:rpm/python2-zope-event@4.2.0-9.2.el8stf?arch=noarch"})));
}
