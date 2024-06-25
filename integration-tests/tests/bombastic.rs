#![allow(clippy::unwrap_used)]

use integration_tests::{
    get_response, id, wait_for_package_search_result, wait_for_sbom_search_result, BombasticContext, FileUtility,
    FixtureKind, HasPushFixture, RequestFactory,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use test_context::test_context;
use time::OffsetDateTime;

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_happy_sbom(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload";
    context.upload_sbom(id, &input).await;
    let output: Value = RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .get("/api/v1/sbom")
        .with_query(&[("id", id)])
        .expect_status(StatusCode::OK)
        .send(context)
        .await
        .1
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(input, output);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn delete_happy_sbom(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete";
    context.upload_sbom(id, &input).await;
    let url = "/api/v1/sbom";
    let query = &[("id", id)];
    let request = RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .with_query(query);
    request
        .clone()
        .get(url)
        .expect_status(StatusCode::OK)
        .send(context)
        .await;
    request
        .clone()
        .delete(url)
        .expect_status(StatusCode::NO_CONTENT)
        .send(context)
        .await;
    request
        .clone()
        .get(url)
        .expect_status(StatusCode::NOT_FOUND)
        .send(context)
        .await;
    request
        .clone()
        .delete(url)
        .expect_status(StatusCode::NO_CONTENT)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn delete_missing_sbom(context: &mut BombasticContext) {
    let request = RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .delete("/api/v1/sbom");
    request
        .clone()
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
    for id in &["", "missing"] {
        request
            .clone()
            .with_query(&[("id", id)])
            .expect_status(StatusCode::NO_CONTENT)
            .send(context)
            .await;
    }
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn reject_no_auth_upload(context: &mut BombasticContext) {
    let input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    RequestFactory::new()
        .post("/api/v1/sbom")
        .with_query(&[("id", "test")])
        .with_json(&input)
        .check_status(|s| s.is_client_error() && *s == StatusCode::UNAUTHORIZED)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn reject_non_manager_upload(context: &mut BombasticContext) {
    let input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    RequestFactory::new()
        .with_provider_user()
        .post("/api/v1/sbom")
        .with_query(&[("id", "test")])
        .with_json(&input)
        .check_status(|s| s.is_client_error() && *s == StatusCode::FORBIDDEN)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn bombastic_sbom_search(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    // We generate a unique id and use it as the SBOM's version for searching
    let key = id("test-search");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let response = wait_for_sbom_search_result(context, &[("q", key)], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn bombastic_package_search(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    // We generate a unique id and use it as the SBOM's version for searching
    let key = id("test-package-search");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let purl = "\"pkg:rpm/redhat/libdnf@0.67.0-3.el9?arch=aarch64\"";

    let response = wait_for_package_search_result(context, &[("q", purl)], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("libdnf"));
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(30_000)]
async fn bombastic_bad_search_queries(context: &mut BombasticContext) {
    let request = RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .get("/api/v1/sbom/search")
        .expect_status(StatusCode::BAD_REQUEST);
    for query in &[
        "unknown:ubi9-container-9.1.0-1782.noarch",
        "ubi9-container-9.1.0-1782.testdata sort:unknown",
    ] {
        request.clone().with_query(&[("q", query)]).send(context).await;
    }
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(120_000)]
async fn bombastic_reindexing(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();
    // We generate a unique id and use it as the SBOM's version for searching
    let key = id("test-reindexing");
    input["packages"][617]["versionInfo"] = json!(key);
    context.upload_sbom(&key, &input).await;

    let response = wait_for_sbom_search_result(context, &[("q", &key)], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));

    let now = OffsetDateTime::now_utc();

    // Push update and check reindex
    context.upload_sbom(&key, &input).await;

    wait_for_sbom_search_result(context, &[("q", key.as_str()), ("metadata", "true")], |response| {
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

    let response = wait_for_sbom_search_result(context, &[("q", &key)], |response| {
        response["total"].as_u64().unwrap() > 0
    })
    .await;
    assert_eq!(response["result"][0]["document"]["name"], json!("ubi9-container"));

    context.delete_sbom(&key).await;

    wait_for_sbom_search_result(context, &[("q", &key)], |response| {
        response["total"].as_u64().unwrap() == 1
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_invalid_type(context: &mut BombasticContext) {
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", "foo")])
        .with_headers(&[("Content-Type", "application/xml")])
        .with_body(b"<foo/>".as_slice())
        .expect_status(StatusCode::BAD_REQUEST)
        .expect_headers(&[("accept", "application/json")])
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn valid_bzip2_encoded(context: &mut BombasticContext) {
    let sbom = include_bytes!("../../bombastic/testdata/ubi8-valid.json.bz2");
    let id = "valid_bzip2_encoded";
    context.push_fixture(FixtureKind::Id(String::from(id)));
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", id)])
        .with_headers(&[("Content-Type", "application/json"), ("Content-Encoding", "bzip2")])
        .with_body(sbom.as_slice())
        .expect_status(StatusCode::CREATED)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn invalid_bzip2_encoded(context: &mut BombasticContext) {
    let sbom = include_bytes!("../../bombastic/testdata/3amp-2.json.bz2");
    let id = "invalid_bzip2_encoded";
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", id)])
        .with_headers(&[("Content-Type", "application/json"), ("Content-Encoding", "bzip2")])
        .with_body(sbom.as_slice())
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_invalid_encoding(context: &mut BombasticContext) {
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", "foo")])
        .with_headers(&[("Content-Type", "application/json"), ("Content-Encoding", "braille")])
        .with_body(b"{}".as_slice())
        .expect_status(StatusCode::BAD_REQUEST)
        .expect_headers(&[("accept-encoding", "bzip2, zstd")])
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_sbom_existing_without_change(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-without-change";
    let api_end_point = format!("api/v1/sbom?id={id}");
    context.upload_sbom(id, &input).await;
    let response: Value = get_response(context, &api_end_point, StatusCode::OK).await.into();
    assert_eq!(input, response, "Content mismatch between request and response");
    context.upload_sbom(id, &input).await;
    let response: Value = get_response(context, &api_end_point, StatusCode::OK).await.into();
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
    let api_end_point = format!("api/v1/sbom?id={id}");
    context.upload_sbom(id, &input1).await;
    let response1: Value = get_response(context, &api_end_point, StatusCode::OK).await.into();
    assert_eq!(input1, response1, "Content mismatch between request and response");
    input1["metadata"]["component"]["name"] = Value::String(String::from("update-sbom-name"));
    context.upload_sbom(id, &input1).await;
    let response2: Value = get_response(context, &api_end_point, StatusCode::OK).await.into();
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
    RequestFactory::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", id)])
        .with_json(&input)
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_empty_file(context: &mut BombasticContext) {
    let file_path = "empty-test.txt";
    let file = context.create_file(&file_path).await;
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/sbom")
        .with_query(&[("id", "test-empty-file-upload")])
        .with_body(&file)
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    RequestFactory::new()
        .with_provider_user()
        .post("/api/v1/sbom")
        .with_query(&[("id", "test-user-not-allowed")])
        .with_json(&input)
        .expect_status(StatusCode::FORBIDDEN)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_upload_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    RequestFactory::new()
        .post("api/v1/sbom")
        .with_query(&[("id", "test-unauthorized")])
        .with_json(&input)
        .expect_status(StatusCode::UNAUTHORIZED)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_delete_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-user-not-allowed";
    context.upload_sbom(id, &input).await;
    RequestFactory::new()
        .with_provider_user()
        .delete("api/v1/sbom")
        .with_query(&[("id", id)])
        .with_json(&input)
        .expect_status(StatusCode::FORBIDDEN)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn sbom_delete_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-unauthorized";
    context.upload_sbom(id, &input).await;
    RequestFactory::new()
        .delete("api/v1/sbom")
        .with_query(&[("id", id)])
        .with_json(&input)
        .expect_status(StatusCode::UNAUTHORIZED)
        .send(context)
        .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_sbom_with_invalid_id(context: &mut BombasticContext) {
    let id = "test-invalid-sbom-id";
    let api_end_point = format!("api/v1/sbom?id={id}");
    get_response(context, &api_end_point, StatusCode::NOT_FOUND).await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_sbom_with_missing_id(context: &mut BombasticContext) {
    let api_end_point = "api/v1/sbom?ID=test";
    get_response(context, &api_end_point, StatusCode::BAD_REQUEST).await;
}
