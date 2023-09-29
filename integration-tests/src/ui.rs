use crate::config::{Config, DriverKind};
use crate::runner::Runner;
use crate::{start_spog, SpogContext, Urlifier};
use async_trait::async_trait;
use reqwest::{StatusCode, Url};
use std::net::TcpListener;
use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;
use test_context::AsyncTestContext;
use thirtyfour::components::{Component, ElementResolver};
use thirtyfour::prelude::*;
use tokio::select;
use trustification_infrastructure::app::http::HttpServerBuilder;

pub struct SpogUiContext {
    pub url: Url,
    pub spog_api: SpogContext,
    pub driver: WebDriver,

    _runner: Option<Runner>,
}

impl Urlifier for SpogUiContext {
    fn base_url(&self) -> &Url {
        &self.url
    }
}

impl Deref for SpogUiContext {
    type Target = SpogContext;

    fn deref(&self) -> &Self::Target {
        &self.spog_api
    }
}

#[async_trait]
impl AsyncTestContext for SpogUiContext {
    async fn setup() -> Self {
        let config = Config::new().await;
        start_ui(&config).await
    }

    async fn teardown(self) {
        println!("Tearing down UI");
        self.driver.quit().await.unwrap();
        self.spog_api.teardown().await;
    }
}

pub async fn start_ui(config: &Config) -> SpogUiContext {
    // If remote server is configured, use it
    if let Some(url) = config.spog_ui.clone() {
        log::debug!("Testing remote spog UI: {url}");
        return SpogUiContext {
            url,
            spog_api: start_spog(config).await,
            driver: start_browser(config).await.unwrap(),
            _runner: None,
        };
    }

    #[cfg(not(feature = "with-services"))]
    panic!("Remote trustification server expected");

    #[cfg(feature = "with-services")]
    {
        // No remote server requested, so fire up UI on ephemeral port
        let listener = TcpListener::bind("localhost:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = Url::parse(&format!("http://localhost:{port}")).unwrap();

        let spog_api = start_spog(config).await;

        let dist_path = config.ui_dist_path.clone().unwrap_or_else(|| "../spog/ui/dist".into());
        log::info!("UI Dist path: {}", dist_path.display());

        let runner = Runner::spawn(move || async move {
            select! {
                biased;

                spog = spog_ui(listener, dist_path) => match spog {
                    Err(e) => {
                        panic!("Error running spog UI: {e:?}");
                    }
                    Ok(()) => {
                        println!("Spog UI exited");
                    }
                },

            }

            Ok(())
        });

        // ensure it's initialized
        let client = reqwest::Client::new();
        loop {
            let response = client.get(url.clone()).send().await.unwrap();
            println!("UI check: {}", response.status());
            if response.status() == StatusCode::OK {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let driver = start_browser(config).await.unwrap();

        // login
        login(&driver, url.clone()).await.unwrap();

        // return the context
        SpogUiContext {
            url,
            spog_api,
            driver,
            _runner: Some(runner),
        }
    }
}

#[cfg(feature = "with-services")]
async fn spog_ui(listener: TcpListener, dist_path: PathBuf) -> anyhow::Result<()> {
    HttpServerBuilder::new()
        .listen(listener)
        .configure(move |svc| {
            svc.service(actix_files::Files::new("/", &dist_path).index_file("index.html"));
        })
        .run()
        .await
}

async fn start_browser(config: &Config) -> anyhow::Result<WebDriver> {
    log::info!("Using driver: {}", config.selenium_driver_kind);
    let caps: Capabilities = match config.selenium_driver_kind {
        DriverKind::Chrome => DesiredCapabilities::chrome().into(),
        DriverKind::Firefox => DesiredCapabilities::firefox().into(),
    };

    let url = config
        .selenium_driver_url
        .as_ref()
        .map(|url| url.as_str())
        .unwrap_or("http://localhost:4444");
    let driver = WebDriver::new(url, caps).await?;

    Ok(driver)
}

#[derive(Clone, Debug, Component)]
struct LoginForm {
    #[base]
    form: WebElement,
    #[by(id = "username")]
    username: ElementResolver<WebElement>,
    #[by(id = "password")]
    password: ElementResolver<WebElement>,
    #[by(id = "kc-login")]
    login: ElementResolver<WebElement>,
}

impl LoginForm {
    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<()> {
        self.username.resolve().await?.send_keys(username).await?;
        self.password.resolve().await?.send_keys(password).await?;
        self.login.resolve().await?.click().await?;
        Ok(())
    }
}

async fn login(driver: &WebDriver, url: Url) -> anyhow::Result<()> {
    driver.goto(url).await?;

    // wait for the tracking consent dialog

    let allow = driver
        .query(By::Css(".pf-v5-c-button.pf-m-primary"))
        .with_text("Allow")
        .first()
        .await?;
    allow.wait_until().clickable().await?;
    allow.click().await?;

    // now wait for the login dialog

    let form: LoginForm = driver.query(By::Id("kc-form")).first().await?.into();
    form.base_element().wait_until().displayed().await?;

    // perform the login

    form.login("admin", "admin123456").await?;

    driver.query(By::Css("h1")).with_text("Trusted Content").first().await?;

    Ok(())
}
