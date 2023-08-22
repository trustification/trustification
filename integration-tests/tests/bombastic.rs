use integration_tests::{
    assert_within_timeout, delete_sbom, get_response, id, upload_sbom, wait_for_event, wait_for_search_result,
    BombasticContext, Urlifier,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;
use tokio::fs::{remove_file, File};
use trustification_auth::client::TokenInjector;
use trustification_index::tantivy::time::OffsetDateTime;
use urlencoding::encode;

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload";
    upload_sbom(context, id, &input).await;
    let response = reqwest::Client::new()
        .get(context.urlify(format!("/api/v1/sbom?id={id}")))
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
    upload_sbom(context, id, &input).await;
    let url = context.urlify(format!("/api/v1/sbom?id={id}"));
    let client = reqwest::Client::new();
    let response = client
        .get(url.clone())
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .delete(url.clone())
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .get(url.clone())
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = client
        .delete(url.clone())
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
async fn test_delete_missing(context: &mut BombasticContext) {
    let client = reqwest::Client::new();
    let response = client
        .delete(context.urlify(format!("/api/v1/sbom")))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = client
        .delete(context.urlify(format!("/api/v1/sbom?id=")))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .delete(context.urlify(format!("/api/v1/sbom?id=missing")))
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
#[ntest::timeout(90_000)]
async fn test_bombastic_search(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();

    // we generate a unique id and use it as the SBOM's version for searching
    let key = id("test-search");
    input["packages"][617]["versionInfo"] = json!(key);

    upload_sbom(context, &key, &input).await;

    wait_for_search_result(context, &[("q", &encode(&key))], Duration::from_secs(30), |response| {
        if response["total"].as_u64().unwrap() >= 1 {
            assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));
            true
        } else {
            false
        }
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn test_bombastic_bad_search_queries(context: &mut BombasticContext) {
    assert_within_timeout(Duration::from_secs(30), async {
        for query in &[
            "unknown:ubi9-container-9.1.0-1782.noarch",
            "ubi9-container-9.1.0-1782.testdata sort:unknown",
        ] {
            let query = encode(query);
            let url = context.urlify(format!("/api/v1/sbom/search?q={query}"));
            let response = reqwest::Client::new()
                .get(url)
                .inject_token(&context.provider.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn test_bombastic_reindexing(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();

    // we generate a unique id and use it as the SBOM's version for searching
    let key = id("test-reindexing");
    input["packages"][617]["versionInfo"] = json!(key);

    upload_sbom(context, &key, &input).await;

    wait_for_search_result(context, &[("q", &encode(&key))], Duration::from_secs(30), |response| {
        if response["total"].as_u64().unwrap() >= 1 {
            assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));
            true
        } else {
            false
        }
    })
    .await;

    let now = OffsetDateTime::now_utc();

    // Push update and check reindex
    upload_sbom(context, &key, &input).await;

    wait_for_search_result(
        context,
        &[("q", &encode(&key)), ("metadata", "true")],
        Duration::from_secs(30),
        |response| {
            if response["total"].as_u64().unwrap() >= 1 {
                let format = &time::format_description::well_known::Rfc3339;
                let ts = OffsetDateTime::parse(
                    response["result"][0]["$metadata"]["indexed_timestamp"]["values"][0]
                        .as_str()
                        .unwrap(),
                    format,
                )
                .unwrap();
                ts > now
            } else {
                false
            }
        },
    )
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn test_bombastic_deletion(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();

    let key = id("test-index-deletion");
    input["packages"][617]["versionInfo"] = json!(key);

    upload_sbom(context, &key, &input).await;

    wait_for_search_result(context, &[("q", &encode(&key))], Duration::from_secs(30), |response| {
        if response["total"].as_u64().unwrap() >= 1 {
            assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));
            true
        } else {
            false
        }
    })
    .await;

    delete_sbom(context, &key).await;

    wait_for_search_result(context, &[("q", &encode(&key))], Duration::from_secs(30), |response| {
        response["total"].as_u64().unwrap() == 1
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_invalid_type(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/sbom?id=foo")))
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
        .post(context.urlify(format!("/api/v1/sbom?id=foo")))
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

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_sbom_existing_without_change(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-without-change";
    let api_end_point = context.urlify(format!("api/v1/sbom?id={id}"));
    upload_sbom(context, id, &input).await;
    let response: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input, response, "Content mismatch between request and response");
    upload_sbom(context, id, &input).await;
    let response: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(
        input, response,
        "Content mismatch between request and response after update"
    );
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_sbom_existing_with_change(context: &mut BombasticContext) {
    let mut input1 = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-with-change";
    let api_end_point = context.urlify(format!("api/v1/sbom?id={id}"));
    upload_sbom(context, id, &input1).await;
    let response1: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input1, response1, "Content mismatch between request and response");
    input1["metadata"]["component"]["name"] = Value::String(String::from("update-sbom-name"));
    upload_sbom(context, id, &input1).await;
    let response2: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(
        input1, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_empty_json(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::json!({});
    let id = "empty-json-upload";
    let client = reqwest::Client::new();
    let url = context.urlify(format!("/api/v1/sbom?id={id}"));
    wait_for_event(Duration::from_secs(30), &context.config, "sbom-failed", id, async {
        let response = client
            .post(url)
            .json(&input)
            .inject_token(&context.provider.provider_manager)
            .await
            .unwrap()
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_empty_file(context: &mut BombasticContext) {
    let file_path = "empty-test.txt";
    let _ = File::create(&file_path).await.expect("file creation failed");
    let file = File::open(&file_path).await.unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=empty-file-upload"))
        .body(file)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    remove_file(&file_path).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-user-not-allowed";
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/sbom?id={id}")))
        .json(&input)
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-unauthorized";
    let response = reqwest::Client::new()
        .post(context.urlify(format!("api/v1/sbom?id={id}")))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-user-not-allowed";
    upload_sbom(context, id, &input).await;
    let response = reqwest::Client::new()
        .delete(context.urlify(format!("api/v1/sbom?id={id}")))
        .json(&input)
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-unauthorized";
    upload_sbom(context, id, &input).await;
    let response = reqwest::Client::new()
        .delete(context.urlify(format!("api/v1/sbom?id={id}")))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_sbom_with_invalid_id(context: &mut BombasticContext) {
    let id = "invalid-sbom-id";
    let api_endpoint = context.urlify(format!("api/v1/sbom?id={id}"));
    get_response(&api_endpoint, StatusCode::NOT_FOUND, &context.provider).await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_sbom_with_missing_id(context: &mut BombasticContext) {
    let api_endpoint = context.urlify(format!("api/v1/sbom?ID=test"));
    get_response(&api_endpoint, StatusCode::BAD_REQUEST, &context.provider).await;
}
