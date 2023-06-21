use integration_tests::{assert_within_timeout, run_test};
use reqwest::StatusCode;
use serde_json::{Map, Value};
use std::time::Duration;

#[test]
fn test_bombastic() {
    run_test(Duration::from_secs(60), async move {
        let client = reqwest::Client::new();
        let input = serde_json::from_str::<Map<String, Value>>(include_str!("../../bombastic/testdata/ubi9-sbom.json"))
            .unwrap();
        let response = client
            .post("http://localhost:8082/api/v1/sbom?id=ubi9")
            .json(&input)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);

        assert_within_timeout(Duration::from_secs(30), async move {
            loop {
                // 1. Check that we can get the SBOM back
                let response = client
                    .get("http://localhost:8082/api/v1/sbom?id=ubi9")
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .unwrap();

                if response.status() == StatusCode::OK {
                    let body: Map<String, Value> = response.json().await.unwrap();
                    assert_eq!(body, input);

                    // 2. Make sure we can search for the SBOM (takes some time)
                    let response = client
                        .get("http://localhost:8082/api/v1/sbom/search?q=")
                        .send()
                        .await
                        .unwrap();

                    assert_eq!(response.status(), StatusCode::OK);
                    let response: Map<String, Value> = response.json().await.unwrap();

                    if let Some(Some(1)) = response.get("total").map(|t| t.as_i64()) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        })
        .await;
        Ok(())
    })
}
