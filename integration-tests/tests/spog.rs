#![allow(clippy::unwrap_used)]

use integration_tests::{id, RequestFactory, SpogContext};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;

#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn spog_version(context: &mut SpogContext) {
    let version: Value = RequestFactory::<&[(&str, &str)], Value>::new()
        .with_provider_user()
        .get("/.well-known/trustification/version")
        .expect_status(StatusCode::OK)
        .send(context)
        .await
        .1
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(version["name"], "spog-api");
}

#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn spog_endpoints(context: &mut SpogContext) {
    let vexination_url = String::from(context.vexination.url.as_str());
    let bombastic_url = String::from(context.bombastic.url.as_str());

    let endpoints: Value = RequestFactory::<&[(&str, &str)], Value>::new()
        .with_provider_user()
        .get("/.well-known/trustification/endpoints")
        .expect_status(StatusCode::OK)
        .send(context)
        .await
        .1
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(endpoints["vexination"], vexination_url);
    assert_eq!(endpoints["bombastic"], bombastic_url);
}

/// SPoG is the entrypoint for the frontend. It exposes a search API, but forwards requests
/// to bombastic of vexination. This requires forwarding the token too. This test is here to
/// test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn spog_search_forward_bombastic(context: &mut SpogContext) {
    let request = RequestFactory::<_, Value>::new()
        .with_provider_user()
        .get("/api/v1/sbom/search");
    request.clone().expect_status(StatusCode::OK).send(context).await;
    // Check forwarding of search errors
    request
        .clone()
        .with_query(&[("q", "unknown:field")])
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

/// SPoG is the entrypoint for the frontend. It exposes a search API, but forwards requests
/// to bombastic of vexination. This requires forwarding the token too. This test is here to
/// test this.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn spog_search_forward_vexination(context: &mut SpogContext) {
    RequestFactory::<&[(&str, &str)], Value>::new()
        .with_provider_user()
        .get("/api/v1/advisory/search")
        .expect_status(StatusCode::OK)
        .send(context)
        .await;
}

#[test_with::env(CRDA_URL)]
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn spog_crda_integration(context: &mut SpogContext) {
    let sbom = include_bytes!("crda/test1.sbom.json");
    RequestFactory::<&[(&str, &str)], Value>::new()
        .set_log_level(log::Level::Info)
        .with_provider_user()
        .post("/api/v1/analyze/report")
        .with_body(sbom.as_slice())
        .expect_status(StatusCode::OK)
        .as_html()
        .send(context)
        .await;
}

/// SPoG API might enrich results from package search with related vulnerabilities. This test checks that this
/// is working as expected for the test data.
#[test_context(SpogContext)]
#[tokio::test]
#[ntest::timeout(120_000)]
async fn spog_search_correlation(context: &mut SpogContext) {
    let mut sbom: Value = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let cpe_id = id("cpe:/a:redhat:service_telemetry_framework:1.5::el8");
    sbom["packages"][883]["externalRefs"][0]["referenceLocator"] = json!(cpe_id);
    let sbom_id = id("test-search-correlation");
    context.bombastic.upload_sbom(&sbom_id, &sbom).await;

    let mut vex: Value = serde_json::from_str(include_str!("testdata/correlation/rhsa-2023_1529.json")).unwrap();
    let vex_id = id("test-search-correlation");
    vex["document"]["tracking"]["id"] = json!(vex_id);
    vex["product_tree"]["branches"][0]["branches"][0]["branches"][0]["product"]["product_identification_helper"]
        ["cpe"] = json!(cpe_id);
    context.vexination.upload_vex(&vex).await;

    let query = &[("q", format!("id:{sbom_id}"))];
    let request = RequestFactory::<_, Value>::new()
        .with_provider_user()
        .get("/api/v1/sbom/search")
        .with_query(query)
        .expect_status(StatusCode::OK);
    // Ensure we can search for the data. We want to allow the
    // indexer time to do its thing, so might need to retry
    loop {
        let payload: Value = request.clone().send(context).await.1.unwrap().try_into().unwrap();
        if payload["total"].as_u64().unwrap() >= 1 {
            assert_eq!(payload["result"][0]["name"], json!("stf-1.5"), "unexpected sbom name");

            let data: spog_model::search::SbomSummary = serde_json::from_value(payload["result"][0].clone()).unwrap();
            log::trace!("Data: {:#?}", data);
            // We need to have some information
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
#[ntest::timeout(60_000)]
async fn spog_dependencies(context: &mut SpogContext) {
    let input = serde_json::from_str(include_str!("testdata/correlation/stf-1.5.json")).unwrap();
    let sbom_id = "test-stf-1.5-guac";
    context.bombastic.upload_sbom(sbom_id, &input).await;

    let request = RequestFactory::<_, Value>::new()
        .with_provider_user()
        .test_status(StatusCode::OK);
    for (purl, endpoint, expected_purl) in &[
        (
            "pkg:rpm/redhat/json-c@0.13.1-0.4.el8",
            "/api/v1/package/related",
            "pkg:rpm/redhat/json-c@0.13.1-0.4.el8?arch=x86_64",
        ),
        (
            "pkg:rpm/redhat/json-c@0.13.1-0.4.el8",
            "/api/v1/package/dependents",
            "pkg:oci/registry.redhat.io/stf/sg-core@sha256:fae8586bc4872450e0f01f99a6202deec63ebd6b2ea8eb5c3f280229fa176da2?tag=5.1.1-3",
        ),
        (
            "pkg:rpm/redhat/python-zope-event@4.2.0-9.2.el8stf",
            "/api/v1/package/dependencies",
            "pkg:rpm/redhat/python2-zope-event@4.2.0-9.2.el8stf?arch=noarch",
        ),
    ] {
        loop {
            let response = request.clone()
                .get(endpoint)
                .with_query(&[("purl", purl)])
                .send(context)
                .await;
            if let (true, result) = response {
                let payload: Value = result.unwrap().try_into().unwrap();
                let data = payload.as_array().unwrap();
                if data.contains(&json!({"purl": expected_purl})) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}
