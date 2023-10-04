use integration_tests::{get_response, id, Urlifier, VexinationContext};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;
use tokio::fs::{remove_file, File};
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vexination_roundtrip(vexination: &mut VexinationContext) {
    let client = reqwest::Client::new();
    let input = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    vexination.upload_vex(&input).await;
    let id = input["document"]["tracking"]["id"].as_str().unwrap();
    let advisory = encode(id);

    loop {
        // 1. Check that we can get the VEX back
        let response = client
            .get(vexination.urlify(format!("/api/v1/vex?advisory={advisory}")))
            .header("Accept", "application/json")
            .inject_token(&vexination.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();

        if response.status() == StatusCode::OK {
            let body: Value = response.json().await.unwrap();
            assert_eq!(body, input);

            // 2. Make sure we can search for the VEX (takes some time)
            let response = client
                .get(vexination.urlify(format!("/api/v1/vex/search?q=%22{advisory}%22")))
                .inject_token(&vexination.provider.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = response.json().await.unwrap();
            if payload["total"].as_u64().unwrap() >= 1 {
                assert_eq!(id, payload["result"][0]["document"]["advisory_id"].as_str().unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn vex_bad_search_queries(context: &mut VexinationContext) {
    // Ensure get expected errors on bad queries
    for query in &["unknown:foo", "foo sort:unknown"] {
        let response = reqwest::Client::new()
            .get(context.urlify(format!("/api/v1/vex/search?q={}", encode(query))))
            .inject_token(&context.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_existing_vex_without_change(vexination: &mut VexinationContext) {
    let mut input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_3408.json")).unwrap();

    // we generate a unique id and use it as the VEX's id for searching
    let key = id("test-unchanged-vex");
    input["document"]["tracking"]["id"] = json!(key);

    let id = encode(&key);
    let url = vexination.urlify(format!("api/v1/vex?advisory={id}"));
    vexination.upload_vex(&input).await;
    let response1: serde_json::Value = get_response(&url, StatusCode::OK, &vexination.provider).await.into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    vexination.upload_vex(&input).await;
    let response2: serde_json::Value = get_response(&url, StatusCode::OK, &vexination.provider).await.into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_existing_vex_with_change(vexination: &mut VexinationContext) {
    let mut input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2021_3029.json")).unwrap();

    // we generate a unique id and use it as the VEX's id for searching
    let key = id("test-changed-vex");
    input["document"]["tracking"]["id"] = json!(key);

    let id = encode(&key);
    let url = vexination.urlify(format!("api/v1/vex?advisory={id}"));
    vexination.upload_vex(&input).await;
    let response1: serde_json::Value = get_response(&url, StatusCode::OK, &vexination.provider).await.into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    input["document"]["title"] = Value::String(String::from("Red Hat Vex Title Updated"));
    vexination.upload_vex(&input).await;
    let response2: serde_json::Value = get_response(&url, StatusCode::OK, &vexination.provider).await.into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_invalid_type(vexination: &mut VexinationContext) {
    let response = reqwest::Client::new()
        .post(vexination.urlify("/api/v1/vex?id=foo"))
        .body("<foo/>")
        .header("Content-Type", "application/xml")
        .inject_token(&vexination.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_invalid_encoding(vexination: &mut VexinationContext) {
    let response = reqwest::Client::new()
        .post(vexination.urlify("/api/v1/vex?id=foo"))
        .body("{}")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "braille")
        .inject_token(&vexination.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_0000)]
async fn upload_vex_empty_json(context: &mut VexinationContext) {
    let id = "test-empty-file-json";
    let input = serde_json::json!({});
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/vex?advisory={id}")))
        .json(&input)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    context.delete_vex(id).await;
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn upload_vex_empty_file(vexination: &mut VexinationContext) {
    let id = "test-empty-file-upload";
    let file_path = "empty-test.txt";
    let _ = File::create(&file_path).await.expect("file creation failed");
    let file = File::open(&file_path).await.unwrap();
    let response = reqwest::Client::new()
        .post(vexination.urlify(format!("/api/v1/vex?advisory={id}")))
        .body(file)
        .inject_token(&vexination.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    remove_file(&file_path).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    vexination.delete_vex(id).await;
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_upload_user_not_allowed(vexination: &mut VexinationContext) {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = encode(input["document"]["tracking"]["id"].as_str().unwrap());
    let reponse = reqwest::Client::new()
        .post(vexination.urlify(format!("/api/v1/vex?advisory={id}")))
        .json(&input)
        .inject_token(&vexination.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(reponse.status(), StatusCode::FORBIDDEN);
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_upload_unauthorized(vexination: &mut VexinationContext) {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = encode(input["document"]["tracking"]["id"].as_str().unwrap());
    let reponse = reqwest::Client::new()
        .post(vexination.urlify(format!("/api/v1/vex?advisory={id}")))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_vex_with_missing_qualifier(vexination: &mut VexinationContext) {
    let api_endpoint = vexination.urlify("api/v1/vex?id=missing_qualifier");
    get_response(&api_endpoint, StatusCode::BAD_REQUEST, &vexination.provider).await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_vex_invalid_advisory(vexination: &mut VexinationContext) {
    let api_endpoint = vexination.urlify("api/v1/vex?advisory=invalid_vex");
    get_response(&api_endpoint, StatusCode::NOT_FOUND, &vexination.provider).await;
}
