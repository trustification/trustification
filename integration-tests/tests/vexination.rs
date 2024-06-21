#![allow(clippy::unwrap_used)]

use integration_tests::{
    get_response, id, FileUtility, FixtureKind, HasPushFixture, PayloadKind, RequestFactory, VexinationContext,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::time::Duration;
use test_context::test_context;
use urlencoding::encode;

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vexination_roundtrip(context: &mut VexinationContext) {
    let input = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    context.upload_vex(&input).await;
    let id = input["document"]["tracking"]["id"].as_str().unwrap();

    loop {
        // 1. Check that we can get the VEX back
        let response = RequestFactory::<_, Value>::new()
            .with_provider_manager()
            .get("/api/v1/vex")
            .with_query(&[("advisory", &id)])
            .with_headers(&[("Accept", "application/json")])
            .test_status(StatusCode::OK)
            .send(context)
            .await;
        if let (true, body) = response {
            assert_eq!(<PayloadKind as TryInto<Value>>::try_into(body.unwrap()).unwrap(), input);

            // 2. Make sure we can search for the VEX (takes some time)
            let payload: Value = RequestFactory::<_, Value>::new()
                .with_provider_manager()
                .get("/api/v1/vex/search")
                .with_query(&[("q", format!("\"{id}\""))])
                .expect_status(StatusCode::OK)
                .send(context)
                .await
                .1
                .unwrap()
                .try_into()
                .unwrap();

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
    let request = RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .get("/api/v1/vex/search")
        .expect_status(StatusCode::BAD_REQUEST);
    for query in &["unknown:foo", "foo sort:unknown"] {
        request.clone().with_query(&[("q", query)]).send(context).await;
    }
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_existing_vex_without_change(context: &mut VexinationContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_3408.json")).unwrap();

    // We generate a unique id and use it as the VEX's id for searching
    let key = id("test-unchanged-vex");
    input["document"]["tracking"]["id"] = json!(key);

    let id = encode(&key);
    let url = format!("api/v1/vex?advisory={id}");
    context.upload_vex(&input).await;
    let response1: Value = get_response(context, &url, StatusCode::OK).await.into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    context.upload_vex(&input).await;
    let response2: Value = get_response(context, &url, StatusCode::OK).await.into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn upload_existing_vex_with_change(context: &mut VexinationContext) {
    let mut input: Value = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2021_3029.json")).unwrap();

    // We generate a unique id and use it as the VEX's id for searching
    let key = id("test-changed-vex");
    input["document"]["tracking"]["id"] = json!(key);

    let id = encode(&key);
    let url = format!("api/v1/vex?advisory={id}");
    context.upload_vex(&input).await;
    let response1: Value = get_response(context, &url, StatusCode::OK).await.into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    input["document"]["title"] = Value::String(String::from("Red Hat Vex Title Updated"));
    context.upload_vex(&input).await;
    let response2: Value = get_response(context, &url, StatusCode::OK).await.into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_invalid_type(context: &mut VexinationContext) {
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/vex")
        .with_query(&[("id", "foo")])
        .with_headers(&[("Content-Type", "application/xml")])
        .with_body(b"<foo/>".as_slice())
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_invalid_encoding(context: &mut VexinationContext) {
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/vex")
        .with_query(&[("id", "foo")])
        .with_headers(&[("Content-Type", "application/json"), ("Content-Encoding", "braille")])
        .with_body(b"{}".as_slice())
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_0000)]
async fn upload_vex_empty_json(context: &mut VexinationContext) {
    let id = "test-empty-file-json";
    let input = serde_json::json!({});
    context.push_fixture(FixtureKind::Id(String::from(id)));
    RequestFactory::new()
        .with_provider_manager()
        .post("/api/v1/vex")
        .with_query(&[("advisory", id)])
        .with_json(&input)
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(90_000)]
async fn upload_vex_empty_file(context: &mut VexinationContext) {
    let id = "test-empty-file-upload";
    let file_path = "empty-test.txt";
    let file = context.create_file(file_path).await;
    context.push_fixture(FixtureKind::Id(String::from(id)));
    RequestFactory::<_, Value>::new()
        .with_provider_manager()
        .post("/api/v1/vex")
        .with_query(&[("advisory", id)])
        .with_body(&file)
        .expect_status(StatusCode::BAD_REQUEST)
        .send(context)
        .await;
}

#[cfg(feature = "admin")]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_upload_user_not_allowed(context: &mut VexinationContext) {
    let input: Value = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = input["document"]["tracking"]["id"].as_str().unwrap();
    RequestFactory::new()
        .with_provider_user()
        .post("/api/v1/vex")
        .with_query(&[("advisory", id)])
        .with_json(&input)
        .expect_status(StatusCode::FORBIDDEN)
        .send(context)
        .await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn vex_upload_unauthorized(context: &mut VexinationContext) {
    let input: Value = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = input["document"]["tracking"]["id"].as_str().unwrap();
    RequestFactory::new()
        .post("/api/v1/vex")
        .with_query(&[("advisory", id)])
        .with_json(&input)
        .expect_status(StatusCode::UNAUTHORIZED)
        .send(context)
        .await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_vex_with_missing_qualifier(context: &mut VexinationContext) {
    let api_end_point = "api/v1/vex?id=missing_qualifier";
    get_response(context, &api_end_point, StatusCode::BAD_REQUEST).await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn get_vex_invalid_advisory(context: &mut VexinationContext) {
    let api_end_point = "api/v1/vex?advisory=invalid_vex";
    get_response(context, &api_end_point, StatusCode::NOT_FOUND).await;
}
