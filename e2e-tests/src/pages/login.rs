use crate::world::E2EWorld;
use cucumber::given;
use std::time::Duration;
use thirtyfour::{
    common::command::By,
    prelude::{ElementWaitable, WebDriverError},
    WebDriver,
};

#[given(expr = "The user is on the Trustification home screen")]
async fn login_to_application(world: &mut E2EWorld) {
    let driver: &WebDriver = world.context.get_driver().unwrap();
    let application = world.application.as_ref().expect("Error").as_str();
    driver.goto(application).await.expect("Failed to load application");
    consent_deny(driver).await;
    let signin_title = driver.title().await.unwrap();
    assert_eq!(signin_title, "Sign in to Trusted Content");
    let elem_signin: By = By::Id("kc-header");
    let txtbx_username: By = By::Id("username");
    let txtbx_password: By = By::Id("password");
    let btn_login: By = By::Id("kc-login");
    driver.find(elem_signin).await.unwrap().wait_until();
    driver
        .find(txtbx_username)
        .await
        .unwrap()
        .send_keys(world.user_name.as_ref().expect("Error").as_str())
        .await
        .expect("Elelment not found");
    driver
        .find(txtbx_password)
        .await
        .unwrap()
        .send_keys(world.password.as_ref().expect("Error").as_str())
        .await
        .expect("Elelment not found");
    driver
        .find(btn_login)
        .await
        .unwrap()
        .click()
        .await
        .expect("Unable to click");
    let trustification_title = driver.title().await.unwrap();
    assert_eq!(trustification_title, "Trustification Console");
    let lnk_menu_home: By = By::XPath("//a[contains(.,'Home')]");
    let _ = wait_for_elem(driver, lnk_menu_home).await;
    let txtbx_search: By = By::XPath("//div[@id='search_terms']//input");
    assert!(driver.find(txtbx_search).await.unwrap().is_displayed().await.unwrap());
}

pub async fn consent_deny(driver: &WebDriver) {
    let elem_consent: By = By::Id("modal-description");
    let btn_consent_deny: By = By::XPath("//button[.='Deny']");
    match driver.find(elem_consent).await {
        Ok(_) => {
            let elem_deny_consent = driver.find(btn_consent_deny).await.unwrap();
            let _ = elem_deny_consent.click().await;
        }
        Err(_) => {}
    };
}

async fn wait_for_elem(driver: &WebDriver, elem: By) -> Result<(), WebDriverError> {
    driver
        .find(elem)
        .await?
        .wait_until()
        .wait(Duration::from_secs(3), Duration::from_millis(1000))
        .error("Element wait timeout")
        .displayed()
        .await
        .expect("Element is not displayed");
    Ok(())
}
