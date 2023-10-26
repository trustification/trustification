use crate::world::E2EWorld;
use cucumber::when;
use thirtyfour::{common::command::By, WebDriver};

#[when(expr = "The user Enters Search for {string} in the search field")]
async fn search_cve_home_screen(world: &mut E2EWorld, cve: String) {
    let driver: &WebDriver = world.context.get_driver().unwrap();
    let txtbx_search: By = By::XPath("//div[@id='search_terms']//input");
    driver.find(txtbx_search).await.unwrap().send_keys(cve).await.unwrap();
    let btn_search: By = By::Id("search");
    driver.find(btn_search).await.unwrap().click().await.unwrap();
}

#[when(expr = "The user Navigates to Home screen and Clicks on Back Button")]
async fn navigate_home_and_click_back(world: &mut E2EWorld) {
    let driver: &WebDriver = world.context.get_driver().unwrap();
    let lnk_menu_home: By = By::XPath("//a[contains(.,'Home')]");
    driver.find(lnk_menu_home).await.unwrap().click().await.unwrap();
    driver.back().await.unwrap();
}
