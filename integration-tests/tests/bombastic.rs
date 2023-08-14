use integration_tests::{
    assert_within_timeout, delete_sbom, get_response, id, upload_sbom, wait_for_event, BombasticContext,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;
use tokio::fs::{remove_file, File};
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload(context: &mut BombasticContext) {
    let input = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload";
    upload_sbom(context.port, id, &input, &context.provider).await;
    let response = reqwest::Client::new()
        .get(format!(
            "http://localhost:{port}/api/v1/sbom?id={id}",
            port = context.port
        ))
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
    upload_sbom(context.port, id, &input, &context.provider).await;
    let url = &format!("http://localhost:{port}/api/v1/sbom?id={id}", port = context.port);
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .delete(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .get(url)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = client
        .delete(url)
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
        .delete(format!("http://localhost:{port}/api/v1/sbom", port = context.port))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = client
        .delete(format!("http://localhost:{port}/api/v1/sbom?id=", port = context.port))
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = client
        .delete(format!(
            "http://localhost:{port}/api/v1/sbom?id=missing",
            port = context.port
        ))
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
async fn bombastic_search(context: &mut BombasticContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../bombastic/testdata/ubi9-sbom.json")).unwrap();

    // we generate a unique id and use it as the SBOM's version for searching
    let key = id("test-search");
    input["packages"][617]["versionInfo"] = json!(key);

    upload_sbom(context.port, &key, &input, &context.provider).await;

    assert_within_timeout(Duration::from_secs(30), async {
        loop {
            let url = format!(
                "http://localhost:{port}/api/v1/sbom/search?q={query}",
                port = context.port,
                query = encode(&key),
            );
            let response = reqwest::Client::new()
                .get(url)
                .inject_token(&context.provider.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = response.json().await.unwrap();
            if payload["total"].as_u64().unwrap() >= 1 {
                assert_eq!(payload["result"][0]["document"]["name"], json!("ubi9-container"));
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // Ensure get expected errors on bad queries
        for query in &[
            "unknown:ubi9-container-9.1.0-1782.noarch",
            "ubi9-container-9.1.0-1782.testdata sort:unknown",
        ] {
            let query = encode(query);
            let url = format!(
                "http://localhost:{port}/api/v1/sbom/search?q={query}",
                port = context.port
            );
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

    delete_sbom(context.port, &key, &context.provider).await;
    assert_within_timeout(Duration::from_secs(30), async {
        loop {
            let url = format!(
                "http://localhost:{port}/api/v1/sbom/search?q={query}",
                port = context.port,
                query = encode(&key),
            );
            let response = reqwest::Client::new()
                .get(url)
                .inject_token(&context.provider.provider_manager)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let payload: Value = response.json().await.unwrap();
            if payload["total"].as_u64().unwrap() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_invalid_type(context: &mut BombasticContext) {
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{port}/api/v1/sbom?id=foo",
            port = context.port
        ))
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
        .post(format!(
            "http://localhost:{port}/api/v1/sbom?id=foo",
            port = context.port
        ))
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
    let api_end_point = format!("api/v1/sbom?id={id}");
    upload_sbom(context.port, id, &input, &context.provider).await;
    let response: Value = get_response(context.port, &api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input, response, "Content mismatch between request and response");
    upload_sbom(context.port, id, &input, &context.provider).await;
    let response: Value = get_response(context.port, &api_end_point, StatusCode::OK, &context.provider)
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
    let api_end_point = format!("api/v1/sbom?id={id}");
    upload_sbom(context.port, id, &input1, &context.provider).await;
    let response1: Value = get_response(context.port, &api_end_point, StatusCode::OK, &context.provider)
        .await
        .into();
    assert_eq!(input1, response1, "Content mismatch between request and response");
    input1["metadata"]["component"]["name"] = Value::String(String::from("update-sbom-name"));
    upload_sbom(context.port, id, &input1, &context.provider).await;
    let response2: Value = get_response(context.port, &api_end_point, StatusCode::OK, &context.provider)
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
    let url = &format!("http://localhost:{port}/api/v1/sbom?id={id}", port = context.port);
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
        .post(format!(
            "http://localhost:{}/api/v1/sbom?id=empty-file-upload",
            context.port
        ))
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
    let api_end_point = format!("api/v1/sbom?id={id}");
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{}/{}", context.port, api_end_point))
        .json(&input)
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    println!("{:?}", response);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-upload-unauthorized";
    let api_end_point = format!("api/v1/sbom?id={id}");
    let response = reqwest::Client::new()
        .post(format!("http://localhost:{}/{}", context.port, api_end_point))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    println!("{:?}", response);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete_user_not_allowed(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-user-not-allowed";
    let api_end_point = format!("api/v1/sbom?id={id}");
    upload_sbom(context.port, id, &input, &context.provider).await;
    let response = reqwest::Client::new()
        .delete(format!("http://localhost:{}/{}", context.port, api_end_point))
        .json(&input)
        .inject_token(&context.provider.provider_user)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    println!("{:?}", response);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_delete_unauthorized(context: &mut BombasticContext) {
    let input: serde_json::Value = serde_json::from_str(include_str!("../../bombastic/testdata/my-sbom.json")).unwrap();
    let id = "test-delete-unauthorized";
    let api_end_point = format!("api/v1/sbom?id={id}");
    upload_sbom(context.port, id, &input, &context.provider).await;
    let response = reqwest::Client::new()
        .delete(format!("http://localhost:{}/{}", context.port, api_end_point))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    println!("{:?}", response);
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_sbom_with_invalid_id(context: &mut BombasticContext) {
    let id = "invalid-sbom-id";
    let api_endpoint = format!("api/v1/sbom?id={id}");
    get_response(context.port, &api_endpoint, StatusCode::NOT_FOUND, &context.provider).await;
}

#[test_context(BombasticContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_sbom_with_missing_id(context: &mut BombasticContext) {
    let api_endpoint = format!("api/v1/sbom?ID=test");
    get_response(context.port, &api_endpoint, StatusCode::BAD_REQUEST, &context.provider).await;
}
