use integration_tests::{assert_within_timeout, get_response, upload_vex, VexinationContext};
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;
use test_context::test_context;
use tokio::fs::{remove_file, File};
use trustification_auth::client::TokenInjector;
use urlencoding::encode;

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_vexination(vexination: &mut VexinationContext) {
    let client = reqwest::Client::new();
    let input = serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    upload_vex(vexination.port, &input, &vexination.provider).await;

    assert_within_timeout(Duration::from_secs(30), async move {
        loop {
            // 1. Check that we can get the VEX back
            let response = client
                .get(format!(
                    "http://localhost:{port}/api/v1/vex?advisory=RHSA-2023%3A1441",
                    port = vexination.port
                ))
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
                    .get(format!(
                        "http://localhost:{port}/api/v1/vex/search?q=",
                        port = vexination.port
                    ))
                    .inject_token(&vexination.provider.provider_manager)
                    .await
                    .unwrap()
                    .send()
                    .await
                    .unwrap();

                assert_eq!(response.status(), StatusCode::OK);
                let payload: Value = response.json().await.unwrap();

                if payload["total"].as_u64().unwrap() >= 1 {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
    })
    .await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_existing_vex_without_change(vexination: &VexinationContext) {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_3408.json")).unwrap();
    let id = encode(&input["document"]["tracking"]["id"].as_str().unwrap());
    let api_endpoint = format!("api/v1/vex?advisory={}", &id);
    upload_vex(vexination.port, &input, &vexination.provider).await;
    let response1: serde_json::Value =
        get_response(vexination.port, &api_endpoint, StatusCode::OK, &vexination.provider)
            .await
            .into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    upload_vex(vexination.port, &input, &vexination.provider).await;
    let response2: serde_json::Value =
        get_response(vexination.port, &api_endpoint, StatusCode::OK, &vexination.provider)
            .await
            .into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_existing_vex_with_change(vexination: &VexinationContext) {
    let mut input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2021_3029.json")).unwrap();
    let id = encode(&input["document"]["tracking"]["id"].as_str().unwrap());
    let api_endpoint = format!("api/v1/vex?advisory={}", &id);
    upload_vex(vexination.port, &mut input, &vexination.provider).await;
    let response1: serde_json::Value =
        get_response(vexination.port, &api_endpoint, StatusCode::OK, &vexination.provider)
            .await
            .into();
    assert_eq!(input, response1, "Content mismatch between request and response");
    input["document"]["title"] = Value::String(String::from("Red Hat Vex Title Updated"));
    upload_vex(vexination.port, &mut input, &vexination.provider).await;
    let response2: serde_json::Value =
        get_response(vexination.port, &api_endpoint, StatusCode::OK, &vexination.provider)
            .await
            .into();
    assert_eq!(
        input, response2,
        "Content mismatch between request and response after update"
    );
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_vex_invalid_type(vexination: &mut VexinationContext) {
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{port}/api/v1/vex?id=foo",
            port = vexination.port
        ))
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
async fn test_vex_invalid_encoding(vexination: &mut VexinationContext) {
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{port}/api/v1/vex?id=foo",
            port = vexination.port
        ))
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

#[ignore = "until we figure out #363"]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_0000)]
async fn test_upload_vex_empty_json(context: &mut VexinationContext) {
    let input = serde_json::json!({});
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{}/api/v1/vex?advisory=empty-file-json",
            context.port
        ))
        .json(&input)
        .inject_token(&context.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    println!("{:?}", response);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[ignore = "until we figure out #363"]
#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_upload_vex_empty_file(vexination: &mut VexinationContext) {
    let file_path = "empty-test.txt";
    let _ = File::create(&file_path).await.expect("file creation failed");
    let file = File::open(&file_path).await.unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "http://localhost:{}/api/v1/vex?advisory=empty-file-upload",
            vexination.port
        ))
        .body(file)
        .inject_token(&vexination.provider.provider_manager)
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    remove_file(&file_path).await.unwrap();
    println!("{:?}", response);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_vex_upload_user_not_allowed(vexination: &mut VexinationContext) {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = encode(&input["document"]["tracking"]["id"].as_str().unwrap());
    let reponse = reqwest::Client::new()
        .post(format!(
            "http://localhost:{}/api/v1/vex?advisory={}",
            vexination.port, id
        ))
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
async fn test_vex_upload_unauthorized(vexination: &mut VexinationContext) {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("../../vexination/testdata/rhsa-2023_1441.json")).unwrap();
    let id = encode(&input["document"]["tracking"]["id"].as_str().unwrap());
    let reponse = reqwest::Client::new()
        .post(format!(
            "http://localhost:{}/api/v1/vex?advisory={}",
            vexination.port, id
        ))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(reponse.status(), StatusCode::UNAUTHORIZED);
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_vex_with_missing_qualifier(vexination: &mut VexinationContext) {
    let api_endpoint = format!("api/v1/vex?id=missing_qualifier");
    get_response(
        vexination.port,
        &api_endpoint,
        StatusCode::BAD_REQUEST,
        &vexination.provider,
    )
    .await;
}

#[test_context(VexinationContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn test_get_vex_invalid_advisory(vexination: &mut VexinationContext) {
    let api_endpoint = format!("api/v1/vex?advisory=invalid_vex");
    get_response(
        vexination.port,
        &api_endpoint,
        StatusCode::NOT_FOUND,
        &vexination.provider,
    )
    .await;
}
