use integration_tests::with_spog;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[test]
fn test_version() {
    with_spog(Duration::from_secs(30), |port| async move {
        let response = reqwest::get(format!("http://localhost:{port}/.well-known/trustification/version"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let version: Value = response.json().await.unwrap();
        assert_eq!(version["name"], "spog-api");
    })
}
