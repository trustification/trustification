use crate::world::E2EWorld;
use cucumber::then;
use thirtyfour::{common::command::By, prelude::ElementWaitable, WebDriver};

#[then(expr = "The list of SBOMs should displayed related to {string}")]
#[then(expr = "The application should preserve page state and retrieve SBOM search results for {string}")]
async fn assert_cve_search_result(world: &mut E2EWorld, sbom: String) {
    let driver: &WebDriver = world.context.get_driver().unwrap();
    let hdr_search_result: By = By::XPath("//h1[.='Search Results']");
    driver
        .find(hdr_search_result)
        .await
        .unwrap()
        .wait_until()
        .displayed()
        .await
        .expect("Header is not displayed");
    let btn_sbom: By = By::XPath("//button/span[contains(.,'SBOMs') and not (contains(.,'dependency'))]");
    driver.find(btn_sbom).await.unwrap().click().await.unwrap();
    let lnk_sbom: By = By::XPath(&"//a[contains(.,'<value>')]".replace("<value>", &sbom));
    assert!(driver.find(lnk_sbom).await.unwrap().is_displayed().await.unwrap());
}
