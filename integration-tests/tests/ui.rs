use integration_tests::SpogUiContext;
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use test_context::test_context;
use thirtyfour::prelude::{ElementQueryable, ElementWaitable};
use thirtyfour::{By, WebDriver, WebElement};

async fn click_nav_link(driver: &WebDriver, label: impl Into<String>) {
    let nav = driver
        .query(By::Css(".pf-v5-c-nav__link"))
        .with_text(label.into())
        .first()
        .await
        .unwrap();
    nav.wait_until().clickable().await.unwrap();
    nav.click().await.unwrap();
}

async fn find_radio_input(driver: &WebDriver, label: impl Into<String>) -> WebElement {
    let label = driver
        .query(By::Css(".pf-v5-c-radio__label"))
        .with_text(label.into())
        .first()
        .await
        .unwrap();

    label.wait_until().displayed().await.unwrap();
    let radio = label.parent().await.unwrap();
    radio.query(By::Tag("input")).first().await.unwrap()
}

#[cfg_attr(not(feature = "ui"), ignore = "UI tests are not enabled")]
#[test_with::env(CRDA_URL)]
#[test_context(SpogUiContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn issue_tc_587(context: &mut SpogUiContext) {
    let driver = &context.driver;

    // go to the "scan SBOM" page
    click_nav_link(driver, "Scan SBOM").await;

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
    assert!(!btn_scan.first().await.unwrap().is_clickable().await.unwrap());
    assert!(btn_clear.first().await.unwrap().is_clickable().await.unwrap());

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
    assert!(!btn_scan.first().await.unwrap().is_clickable().await.unwrap());
    assert!(!btn_clear.first().await.unwrap().is_clickable().await.unwrap());

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
    assert!(!btn_scan.first().await.unwrap().is_clickable().await.unwrap());
    assert!(btn_clear.first().await.unwrap().is_clickable().await.unwrap());
}

#[cfg_attr(not(feature = "ui"), ignore = "UI tests are not enabled")]
#[test_context(SpogUiContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn ensure_default_values(context: &mut SpogUiContext) {
    let driver = &context.driver;

    // trigger the search, with no input

    let button = driver.query(By::Id("search")).first().await.unwrap();
    button.wait_until().clickable().await.unwrap();
    button.click().await.unwrap();

    // find the "any time" option, ensure it's selected

    let any_time = find_radio_input(driver, "Any time").await;

    assert_eq!(any_time.value().await.unwrap().unwrap(), "on");
}

#[cfg_attr(not(feature = "ui"), ignore = "UI tests are not enabled")]
#[test_context(SpogUiContext)]
#[tokio::test]
#[ntest::timeout(60_000)]
async fn ensure_page_state(context: &mut SpogUiContext) {
    let driver = &context.driver;

    // trigger the search, with no input

    let terms = driver
        .query(By::Id("search_terms"))
        .first()
        .await
        .unwrap()
        .query(By::Tag("input"))
        .first()
        .await
        .unwrap();
    terms.wait_until().displayed().await.unwrap();
    terms.send_keys("foo").await.unwrap();

    let button = driver.query(By::Id("search")).first().await.unwrap();
    button.wait_until().clickable().await.unwrap();
    button.click().await.unwrap();

    // find the "This year" option, select it

    let this_year = find_radio_input(driver, "This year").await;
    this_year.click().await.unwrap();

    assert_eq!(this_year.value().await.unwrap().unwrap(), "on");

    // navigate away

    click_nav_link(driver, "Home").await;

    // wait for the page to load

    assert_eq!(driver.current_url().await.unwrap().path(), "/");

    // press back button

    driver.back().await.unwrap();

    // ensure the page is loaded

    assert_eq!(driver.current_url().await.unwrap().path(), "/search/foo");

    // fetch element again

    let this_year = find_radio_input(driver, "This year").await;

    // ensure it's still "on"

    assert_eq!(this_year.value().await.unwrap().unwrap(), "on");
}
