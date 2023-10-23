use std::{time, thread};

use thirtyfour::{WebDriver, common::command::By, prelude::ElementWaitable};
use crate::world::E2EWorld;
use cucumber::{given, then, when};

#[given(expr = "User login to the trustification with credentials")]
async fn login_to_application(world: &mut E2EWorld){
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
    driver.find(txtbx_username).await.unwrap().send_keys(world.user_name.as_ref().expect("Error").as_str()).await.expect("Elelment not found");
    driver.find(txtbx_password).await.unwrap().send_keys(world.password.as_ref().expect("Error").as_str()).await.expect("Elelment not found");
    driver.find(btn_login).await.unwrap().click().await.expect("Unable to click");
    let trustification_title = driver.title().await.unwrap();
    assert_eq!(trustification_title, "Trustification Console");
}

pub async fn consent_deny(driver: &WebDriver){
    let elem_consent: By = By::Id("modal-description");
    let btn_consent_deny: By = By::XPath("//button[.='Deny']");
    match driver.find(elem_consent).await{
        Ok(_)=>{
            let elem_deny_consent = driver.find(btn_consent_deny).await.unwrap();
            elem_deny_consent.click().await;
        },
        Err(_)=>{},
    };
}
