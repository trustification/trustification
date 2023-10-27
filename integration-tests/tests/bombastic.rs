use integration_tests::{get_response, id, wait_for_search_result, BombasticContext, Urlifier};
use reqwest::StatusCode;
use serde_json::{json, Value};
use test_context::test_context;
use time::OffsetDateTime;
use tokio::fs::{remove_file, File};
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_happy_sbom(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload";
    context.upload_sbom(id, &input).await;
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
async fn delete_happy_sbom(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete";
    context.upload_sbom(id, &input).await;
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
async fn delete_missing_sbom(context: &mut BombasticContext) {
    let client = reqwest::Client::new();
    let response = client
        .delete(context.urlify("/api/v1/sbom"))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = client
        .delete(context.urlify("/api/v1/sbom?id="))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .delete(context.urlify("/api/v1/sbom?id=missing"))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn reject_no_auth_upload(context: &mut BombasticContext) {
    let input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=test"))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn reject_non_manager_upload(context: &mut BombasticContext) {
    let input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=test"))
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .json(&input)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn bombastic_search(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    // we generate a unique id and use it as the SBOM's version for searching
    let key = id("test-search");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let response = wait_for_search_result(context, &[("q", &encode(&key))], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn bombastic_bad_search_queries(context: &mut BombasticContext) {
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
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(120_000)]
async fn bombastic_reindexing(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    // we generate a unique id and use it as the SBOM's version for searching
    let key = id("test-reindexing");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let response = wait_for_search_result(context, &[("q", &encode(&key))], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));

    let now = OffsetDateTime::now_utc();

    // Push update and check reindex
    context.upload_sbom(&key, &input).await;

    wait_for_search_result(context, &[("q", &encode(&key)), ("metadata", "true")], |response| {
        response["total"].as_u64().filter(|&t| t > 0).is_some_and(|_| {
            let format = &time::format_description::well_known::Rfc3339;
            let ts = OffsetDateTime::parse(
                response["result"][0]["$metadata"]["indexed_timestamp"]["values"][0]
                    .as_str()
                    .unwrap(),
                format,
            )
            .unwrap();
            ts > now
        })
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn bombastic_deletion(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    let key = id("test-index-deletion");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let response = wait_for_search_result(context, &[("q", &encode(&key))], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));

    context.delete_sbom(&key).await;

    wait_for_search_result(context, &[("q", &encode(&key))], |response| {
        response["total"].as_u64().unwrap() == 1
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_invalid_type(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=foo"))
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
async fn valid_bzip2_encoded(context: &mut BombasticContext) {
    let sbom = include_bytes!("../../bombastic/testdata/ubi8-valid.json.bz2");
    let id = "valid_bzip2_encoded";
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/sbom?id={id}")))
        .body(sbom.as_slice())
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "bzip2")
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    context.delete_sbom(id).await
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn invalid_bzip2_encoded(context: &mut BombasticContext) {
    let sbom = include_bytes!("../../bombastic/testdata/3amp-2.json.bz2");
    let id = "invalid_bzip2_encoded";
    let response = reqwest::Client::new()
        .post(context.urlify(format!("/api/v1/sbom?id={id}")))
        .body(sbom.as_slice())
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "bzip2")
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_invalid_encoding(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=foo"))
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
async fn upload_sbom_existing_without_change(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-without-change";
    let api_end_point = context.urlify(format!("api/v1/sbom?id={id}"));
    context.upload_sbom(id, &input).await;
    let response: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input, response, "Content mismatch between request and response");
    context.upload_sbom(id, &input).await;
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
async fn upload_sbom_existing_with_change(context: &mut BombasticContext) {
    let mut input1 = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-with-change";
    let api_end_point = context.urlify(format!("api/v1/sbom?id={id}"));
    context.upload_sbom(id, &input1).await;
    let response1: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input1, response1, "Content mismatch between request and response");
    input1["metadata"]["component"]["name"] = Value::String(String::from("update-sbom-name"));
    context.upload_sbom(id, &input1).await;
    let response2: Value = get_response(&api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(
        input1, response2,
        "Content mismatch between request and response after update"
    );
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_empty_json(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::json!({});
    let id = "test-empty-json-upload";
    let client = reqwest::Client::new();
    let url = context.urlify(format!("/api/v1/sbom?id={id}"));
    let response = client
        .post(url)
        .json(&input)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_empty_file(context: &mut BombasticContext) {
    let file_path = "empty-test.txt";
    let _ = File::create(&file_path).await.expect("file creation failed");
    let file = File::open(&file_path).await.unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=test-empty-file-upload"))
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

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("/api/v1/sbom?id=test-user-not-allowed"))
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
async fn sbom_upload_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let response = reqwest::Client::new()
        .post(context.urlify("api/v1/sbom?id=test-unauthorized"))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_delete_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-user-not-allowed";
    context.upload_sbom(id, &input).await;
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
async fn sbom_delete_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-unauthorized";
    context.upload_sbom(id, &input).await;
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
async fn get_sbom_with_invalid_id(context: &mut BombasticContext) {
    let id = "test-invalid-sbom-id";
    let api_endpoint = context.urlify(format!("api/v1/sbom?id={id}"));
    get_response(&api_endpoint, StatusCode::NOT_FOUND, &context.provider).await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_sbom_with_missing_id(context: &mut BombasticContext) {
    let api_endpoint = context.urlify("api/v1/sbom?ID=test");
    get_response(&api_endpoint, StatusCode::BAD_REQUEST, &context.provider).await;
}
