mod pages;
mod world;
use cucumber::{cli, writer, World, WriterExt};
use futures::FutureExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::{env, result::Result};
use std::{fs::File, time::Duration};
use thirtyfour::prelude::*;
use thirtyfour::{DesiredCapabilities, WebDriver};
use world::{E2EContext, E2EWorld};

#[derive(cli::Args, Clone)] // re-export of `clap::Args`
pub struct E2Ecliparser {
    ///Application URL under test
    #[arg(long)]
    pub application: String,
    ///User Name to login to Application
    #[arg(long)]
    pub user_name: String,
    ///Password to login to Application
    #[arg(long)]
    pub password: String,
    /////Select (chrome/firefox) to run the Application
    //#[arg(long)]
    //pub browser: String,
    /////Select (chrome/firefox) to run the Application
    //#[arg(long)]
    //pub browsercap: String,
}

pub fn fetch_driver() {
    if let Result::Err(_) = std::env::var("driver_path") {
        println!("Configuring Webdriver, It may take sometime. Please wait...");
        let cargo_path = env::var("CARGO").expect("Cargo installation not available");
        let output = Command::new("sh")
            .args(["./src/scripts/env.sh", "-s", cargo_path.as_str()])
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to run the shell script");
        if output.status.success() {
            let mut driver_path = String::from_utf8_lossy(&output.stdout).to_string();
            driver_path = driver_path.trim().to_string();
            println!("Driver Path from script {}", &driver_path);
            env::set_var("driver_path", &driver_path);
            println!("driver path {}", &driver_path);
            Command::new(driver_path)
                .spawn()
                .expect("Failed to run the shell script");
        } else {
            eprintln!("Command failed with an error {:?}", String::from_utf8(output.stderr));
            std::process::exit(1);
        }
    }
}

pub fn driver_teardown() {
    if let Result::Ok(_) = std::env::var("driver_path") {
        println!("Removing Chromedriver...");
        Command::new("sh")
            .args(["./src/scripts/env.sh", "-t"])
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to run the shell script");
    }
}

pub fn load_data() {
    println!("Loading Test data for localhost, it might take sometime...");
    let cargo_path = env::var("CARGO").expect("Cargo installation not available");
    let output = Command::new("sh")
        .args(["./src/scripts/env.sh", "-d", cargo_path.as_str()])
        .output()
        .expect("Failed to run the shell script");
    if output.status.success() {
        println!("Data loaded successfully!");
    } else {
        eprintln!("Command failed with an error: {:?}", String::from_utf8(output.stderr));
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    if let Result::Err(_) = env::var("driver_path") {
        fetch_driver();
    }
    let junit_output_file =
        File::create(format!("{}/junit.xml", env!("CARGO_MANIFEST_DIR"))).expect("Error file creation");
    let json_output_file =
        File::create(format!("{}/cucumber.json", env!("CARGO_MANIFEST_DIR"))).expect("Error file creation");
    let opts = cli::Opts::<_, _, _, E2Ecliparser>::parsed();
    let _option = opts.custom.clone();
    let application = _option.application.to_owned();
    if application.contains("localhost") {
        load_data();
    }
    let opts_custom = Arc::new(_option);
    E2EWorld::cucumber()
        .before(move |_, _, _, world| {
            {
                let opts_custom = Arc::clone(&opts_custom);
                let mut context = E2EContext::new();
                let serverurl = "http://localhost:9515";
                Box::pin(async move {
                    if let Result::Ok(_) = env::var("driver_path") {
                        let mut caps = DesiredCapabilities::chrome();
                        let _ = caps.set_no_sandbox();
                        let _ = caps.set_disable_dev_shm_usage();
                        let _ = caps.add_arg("start-maximized");
                        let driver = WebDriver::new(serverurl, caps)
                            .await
                            .expect("Error while creating Webdriver");
                        let delay = Duration::new(10, 0);
                        driver.set_implicit_wait_timeout(delay).await.expect("Error on wait");
                        context.insert(driver);
                        world.context = Arc::new(context);
                        world.application = Some(opts_custom.application.clone());
                        world.user_name = Some(opts_custom.user_name.clone());
                        world.password = Some(opts_custom.password.clone());
                    } else {
                        println!("Make sure the driver is configured!!!");
                        std::process::exit(1);
                    }
                })
            }
            .boxed_local()
        })
        .with_cli(opts)
        .after(move |_, _, _, _, world| {
            async move {
                if let Some(world) = world {
                    let web_driver: &WebDriver = world.context.get_driver().unwrap();
                    //The WebDriver is defined using Arc insider E2Eworld and quit will kill all the earlier references
                    web_driver.clone().quit().await.unwrap();
                }
            }
            .boxed_local()
        })
        .with_writer(
            writer::Libtest::or_basic()
                .tee::<E2EWorld, _>(writer::JUnit::for_tee(junit_output_file, writer::Verbosity::default()))
                .tee::<E2EWorld, _>(writer::Json::for_tee(json_output_file))
                .normalized(),
        )
        .run("tests/features/")
        .await;
    driver_teardown();
}
