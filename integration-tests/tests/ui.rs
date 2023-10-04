use integration_tests::SpogUiContext;
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use test_context::test_context;
use thirtyfour::prelude::{ElementQueryable, ElementWaitable};
use thirtyfour::By;

#[cfg_attr(not(feature = "ui"), ignore = "UI tests are not enabled")]
#[test_context(SpogUiContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn issue_tc_587(context: &mut SpogUiContext) {
    let driver = &context.driver;

    // go to the "scan SBOM" page

    let nav = driver
        .query(By::Css(".pf-v5-c-nav__link"))
        .with_text("Scan SBOM")
        .first()
        .await
        .unwrap();
    nav.wait_until().clickable().await.unwrap();
    nav.click().await.unwrap();

    // wait for the page to load

    let input = driver
        .query(By::Css(r#".tc-c-drop-area input[type="file"]"#))
        .first()
        .await
        .unwrap();
    input.wait_until().enabled().await.unwrap();

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(include_bytes!("testdata/crda/wrong-version.json"))
        .unwrap();
    file.flush().unwrap();

    input.send_keys(file.path().to_str().unwrap()).await.unwrap();

    // check state

    let btn_scan = driver.query(By::Id("scanner-scan"));
    let btn_clear = driver.query(By::Id("scanner-clear"));
    let message = driver.query(By::Css("#scanner-help-text .pf-v5-c-helper-text__item-text"));

    message
        .first()
        .await
        .unwrap()
        .wait_until()
        .has_text("Failed to parse SBOM as CycloneDX 1.3: Unsupported CycloneDX version: 1.4")
        .await
        .unwrap();
    assert_eq!(btn_scan.first().await.unwrap().is_clickable().await.unwrap(), false);
    assert_eq!(btn_clear.first().await.unwrap().is_clickable().await.unwrap(), true);

    // now clear it again

    btn_clear.first().await.unwrap().click().await.unwrap();

    // message should switch back

    log::info!("Wait for the message to be reset");

    message
        .first()
        .await
        .unwrap()
        .wait_until()
        .wait(Duration::from_secs(1), Duration::from_millis(100))
        .error("Reset error message")
        .has_text("Requires an SBOM")
        .await
        .unwrap();
    assert_eq!(btn_scan.first().await.unwrap().is_clickable().await.unwrap(), false);
    assert_eq!(btn_clear.first().await.unwrap().is_clickable().await.unwrap(), false);

    // load it again

    input.send_keys(file.path().to_str().unwrap()).await.unwrap();

    // and we should get back the version error

    log::info!("Waiting again for the version error");

    message
        .first()
        .await
        .unwrap()
        .wait_until()
        .has_text("Failed to parse SBOM as CycloneDX 1.3: Unsupported CycloneDX version: 1.4")
        .await
        .unwrap();
    assert_eq!(btn_scan.first().await.unwrap().is_clickable().await.unwrap(), false);
    assert_eq!(btn_clear.first().await.unwrap().is_clickable().await.unwrap(), true);
}
