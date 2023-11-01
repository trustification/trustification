use std::time::Duration;

use integration_tests::{id, SpogContext, Urlifier};
use reqwest::StatusCode;
use serde_json::{json, Value};
use test_context::test_context;
use trustification_auth::client::TokenInjector;

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

#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn spog_endpoints(context: &mut SpogContext) {
    let vexination_url = String::from(context.vexination.url.as_str());
    let bombastic_url = String::from(context.bombastic.url.as_str());

    let response = reqwest::Client::new()
        .get(context.urlify("/.well-known/trustification/endpoints"))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let endpoints: Value = response.json().await.unwrap();
    assert_eq!(endpoints["vexination"], vexination_url);
    assert_eq!(endpoints["bombastic"], bombastic_url);
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
        .get(context.urlify("/api/v1/sbom/search"))
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
        .get(context.urlify("/api/v1/sbom/search"))
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
    let mut sbom: serde_json::Value = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let cpe_id = id("cpe:/a:redhat:service_telemetry_framework:1.5::el8");
    sbom["packages"][883]["externalRefs"][0]["referenceLocator"] = json!(cpe_id);
    let sbom_id = id("test-search-correlation");
    context.bombastic.upload_sbom(&sbom_id, &sbom).await;

    let mut vex: serde_json::Value =
        serde_json::from_str(include_str!("testdata/correlation/rhsa-2023_1529.json")).unwrap();
    let vex_id = id("test-search-correlation");
    vex["document"]["tracking"]["id"] = json!(vex_id);
    vex["product_tree"]["branches"][0]["branches"][0]["branches"][0]["product"]["product_identification_helper"]
        ["cpe"] = json!(cpe_id);
    context.vexination.upload_vex(&vex).await;

    let client = reqwest::Client::new();
    // Ensure we can search for the data. We want to allow the
    // indexer time to do its thing, so might need to retry
    loop {
        let response = client
            .get(context.urlify(format!("/api/v1/sbom/search?q=id%3A{sbom_id}")))
            .inject_token(&context.provider.provider_user)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "unexpected status from search");
        let payload: Value = response.json().await.unwrap();
        if payload["total"].as_u64().unwrap() >= 1 {
            assert_eq!(payload["result"][0]["name"], json!("stf-1.5"), "unexpected sbom name");

            let data: spog_model::search::SbomSummary = serde_json::from_value(payload["result"][0].clone()).unwrap();
            // println!("Data: {:?}", data);
            // we need to have some information
            assert!(data.advisories.is_some(), "missing advisories");
            // Data might not be available until vex index is synced
            let advisories = data.advisories.unwrap();
            if advisories > 0 {
                assert_eq!(advisories, 1, "too many advisories found");
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// SPoG is the entrypoint for the frontend. It exposes an dependencies API, but forwards requests
/// to Guac. This test is here to test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn spog_dependencies(context: &mut SpogContext) {
    let input = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let sbom_id = "test-stf-1.5-guac";
    context.bombastic.upload_sbom(sbom_id, &input).await;

    let client = reqwest::Client::new();

    let purl: &str = "pkg:rpm/redhat/json-c@0.13.1-0.4.el8";

    loop {
        let response = client
            .get(context.urlify("/api/v1/package/related"))
            .query(&[("purl", purl)])
            .inject_token(&context.provider.provider_user)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        if response.status() == StatusCode::OK {
            let payload: Value = response.json().await.unwrap();
            let pkgs = payload.as_array().unwrap();
            if pkgs.contains(&json!({"purl": "pkg:rpm/json-c@0.13.1-0.4.el8?arch=x86_64"})) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let response = client
        .get(context.urlify("/api/v1/package/dependents"))
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
        .get(context.urlify("/api/v1/package/dependencies"))
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
