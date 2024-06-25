#![allow(clippy::unwrap_used)]

mod bom;
mod config;
mod provider;
mod spog;
mod ui;
mod vex;

pub mod runner;

pub use bom::*;
pub use provider::*;
pub use spog::*;
pub use ui::*;
pub use vex::*;

use async_trait::async_trait;
use core::future::Future;
use reqwest::{StatusCode, Url};
use serde::ser::Serialize;
use serde_json::Value;
use spog_api::DEFAULT_CRDA_PAYLOAD_LIMIT;
use std::{net::TcpListener, time::Duration};
use tokio::{
    fs::{remove_file, File},
    select,
};
use trustification_auth::{auth::AuthConfigArguments, client::TokenInjector, devmode, swagger_ui::SwaggerUiOidcConfig};
use trustification_event_bus::{EventBusConfig, EventBusType};
use trustification_index::IndexConfig;
use trustification_infrastructure::InfrastructureConfig;
use trustification_storage::StorageConfig;

const STORAGE_ENDPOINT: &str = "http://localhost:9000";
const KAFKA_BOOTSTRAP_SERVERS: &str = "localhost:9092";

pub fn tcp_connection() -> (TcpListener, u16, Url) {
    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = Url::parse(&format!("http://localhost:{port}")).unwrap();

    (listener, port, url)
}

#[derive(Copy, Clone)]
pub enum ValueTester<T: Eq> {
    Ignore,
    Assert(T),
    Check(fn(&T) -> bool),
    Test(T),
}

#[derive(Copy, Clone)]
pub enum RequestKind<'a> {
    Get(&'a str),
    Post(&'a str),
    Delete(&'a str),
}

#[derive(Copy, Clone)]
pub enum BodyKind<'a> {
    Bytes(&'a [u8]),
    Stream(&'a File),
}

impl<'a> From<&'a [u8]> for BodyKind<'a> {
    fn from(s: &'a [u8]) -> Self {
        BodyKind::Bytes(s)
    }
}

impl<'a> From<&'a File> for BodyKind<'a> {
    fn from(s: &'a File) -> Self {
        BodyKind::Stream(s)
    }
}

#[derive(Clone, Debug)]
pub enum PayloadKind {
    Text(String),
    Json(Value),
}

impl TryFrom<PayloadKind> for String {
    type Error = &'static str;

    fn try_from(p: PayloadKind) -> Result<Self, Self::Error> {
        match p {
            PayloadKind::Text(s) => Ok(s),
            _ => Err("Only PayloadKind::Text can be converted to String"),
        }
    }
}

impl TryFrom<PayloadKind> for Value {
    type Error = &'static str;

    fn try_from(p: PayloadKind) -> Result<Self, Self::Error> {
        match p {
            PayloadKind::Json(v) => Ok(v),
            _ => Err("Only PayloadKind::Json can be converted to Value"),
        }
    }
}

// To win over Rust's borrow checker, we cannot use
// `query.map_or(builder, |q| builder.query(q))` but we must trick it via trait
pub trait TryQuery<T: Serialize + ?Sized> {
    fn try_query(self, query: Option<&T>) -> Self;
}

impl<T: Serialize + ?Sized> TryQuery<T> for reqwest::RequestBuilder {
    fn try_query(self, query: Option<&T>) -> Self {
        if let Some(q) = query {
            return self.query(q);
        }
        self
    }
}

pub trait TryJson<T: Serialize + ?Sized> {
    fn try_json(self, json: Option<&T>) -> Self;
}

impl<T: Serialize + ?Sized> TryJson<T> for reqwest::RequestBuilder {
    fn try_json(self, json: Option<&T>) -> Self {
        if let Some(j) = json {
            return self.json(j);
        }
        self
    }
}

#[async_trait]
pub trait TryBody {
    async fn try_body<'a>(self, body: Option<BodyKind<'a>>) -> Self;
}

#[async_trait]
impl TryBody for reqwest::RequestBuilder {
    async fn try_body<'a>(self, body: Option<BodyKind<'a>>) -> Self {
        if let Some(b) = body {
            return match b {
                BodyKind::Bytes(s) => self.body(Vec::from(s)),
                BodyKind::Stream(s) => self.body(s.try_clone().await.unwrap()),
            };
        }
        self
    }
}

#[async_trait]
pub trait TryInjectToken: Sized + Send + Sync {
    async fn try_inject_token<T: IntoTokenProvider + Sync>(self, context: &T, provider: Option<ProviderKind>) -> Self;
}

#[async_trait]
impl TryInjectToken for reqwest::RequestBuilder {
    async fn try_inject_token<T: IntoTokenProvider + Sync>(self, context: &T, provider: Option<ProviderKind>) -> Self {
        if let Some(p) = provider {
            return self.inject_token(context.token_provider(p)).await.unwrap();
        }
        self
    }
}

#[derive(Clone)]
pub struct RequestFactory<'a, T: Serialize + ?Sized, U: Serialize + ?Sized> {
    request: RequestKind<'a>,
    provider_kind: Option<ProviderKind>,
    headers: Option<&'a [(&'a str, &'a str)]>,
    query: Option<&'a T>,
    json: Option<&'a U>,
    body: Option<BodyKind<'a>>,
    status: ValueTester<StatusCode>,
    expected_headers: Option<&'a [(&'a str, &'a str)]>,
    log_level: log::Level,
    payload_as_text: bool,
}

impl<T: Serialize + ?Sized, U: Serialize + ?Sized> Default for RequestFactory<'_, T, U> {
    fn default() -> Self {
        Self {
            request: RequestKind::Get("/"),
            provider_kind: None,
            headers: None,
            query: None,
            json: None,
            body: None,
            status: ValueTester::Assert(StatusCode::OK),
            expected_headers: None,
            log_level: log::Level::Trace,
            payload_as_text: false,
        }
    }
}

impl<'a, T: Serialize + ?Sized, U: Serialize + ?Sized> RequestFactory<'a, T, U> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(mut self, endpoint: &'a str) -> Self {
        self.request = RequestKind::Get(endpoint);
        self
    }

    pub fn post(mut self, endpoint: &'a str) -> Self {
        self.request = RequestKind::Post(endpoint);
        self
    }

    pub fn delete(mut self, endpoint: &'a str) -> Self {
        self.request = RequestKind::Delete(endpoint);
        self
    }

    pub fn with_provider_user(mut self) -> Self {
        self.provider_kind = Some(ProviderKind::User);
        self
    }

    pub fn with_provider_manager(mut self) -> Self {
        self.provider_kind = Some(ProviderKind::Manager);
        self
    }

    pub fn with_headers(mut self, headers: &'a [(&'a str, &'a str)]) -> Self {
        self.headers = Some(headers);
        self
    }

    pub fn with_query(mut self, query: &'a T) -> Self {
        self.query = Some(query);
        self
    }

    pub fn with_json(mut self, json: &'a U) -> Self {
        self.json = Some(json);
        self
    }

    pub fn with_body<V: Into<BodyKind<'a>>>(mut self, body: V) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn ignore_status(mut self) -> Self {
        self.status = ValueTester::Ignore;
        self
    }

    pub fn expect_status(mut self, status_code: StatusCode) -> Self {
        self.status = ValueTester::Assert(status_code);
        self
    }

    pub fn check_status(mut self, check: fn(&StatusCode) -> bool) -> Self {
        self.status = ValueTester::Check(check);
        self
    }

    pub fn test_status(mut self, status_code: StatusCode) -> Self {
        self.status = ValueTester::Test(status_code);
        self
    }

    pub fn expect_headers(mut self, headers: &'a [(&'a str, &'a str)]) -> Self {
        self.expected_headers = Some(headers);
        self
    }

    pub fn set_log_level(mut self, level: log::Level) -> Self {
        self.log_level = level;
        self
    }

    pub fn as_html(mut self) -> Self {
        self.payload_as_text = true;
        self
    }

    pub fn as_json(mut self) -> Self {
        self.payload_as_text = false;
        self
    }

    pub async fn send<V: Urlifier + IntoTokenProvider + Sync>(&self, context: &V) -> (bool, Option<PayloadKind>) {
        let client = reqwest::Client::new();
        let builder = match self.request {
            RequestKind::Get(endpoint) => client.get(context.urlify(endpoint)),
            RequestKind::Post(endpoint) => client.post(context.urlify(endpoint)),
            RequestKind::Delete(endpoint) => client.delete(context.urlify(endpoint)),
        };
        let mut builder = builder.try_query(self.query);
        if let Some(headers) = self.headers {
            for (k, v) in headers {
                builder = builder.header(*k, *v);
            }
        }
        let response = builder
            .try_json(self.json)
            .try_inject_token(context, self.provider_kind)
            .await
            .try_body(self.body)
            .await
            .send()
            .await
            .unwrap();
        log::log!(self.log_level, "Response: {:#?}", response);
        let status_code = response.status();
        match self.status {
            ValueTester::Ignore => (),
            ValueTester::Assert(value) => {
                assert_eq!(
                    status_code, value,
                    "Expected response code does not match with actual response",
                );
            }
            ValueTester::Check(check) => {
                assert!(check(&status_code));
            }
            ValueTester::Test(value) => {
                if status_code != value {
                    return (false, None);
                }
            }
        };
        if let Some(headers) = self.expected_headers {
            for (k, v) in headers {
                assert_eq!(response.headers().get(*k).unwrap(), v);
            }
        }
        let payload = if self.payload_as_text {
            response.text().await.map(|x| PayloadKind::Text(x)).ok()
        } else {
            response.json().await.map(|x| PayloadKind::Json(x)).ok()
        };
        log::log!(self.log_level, "Response payload: {:#?}", payload);
        (true, payload)
    }
}

pub async fn get_response<T: Urlifier + IntoTokenProvider + Sync>(
    context: &T,
    endpoint: &str,
    expected_status: StatusCode,
) -> Option<Value> {
    RequestFactory::<&[(&str, &str)], Value>::new()
        .with_provider_manager()
        .get(endpoint)
        .expect_status(expected_status)
        .send(context)
        .await
        .1
        .map(|p| p.try_into().unwrap())
}

pub async fn wait_on_service<T: Urlifier + IntoTokenProvider + Sync>(context: &T, service: &str, key: &str) {
    let endpoint = format!("/api/v1/{service}");
    let query = &[(key, "none")];
    let request: RequestFactory<'_, _, Value> = RequestFactory::new()
        .with_provider_user()
        .get(&endpoint)
        .with_query(query)
        .test_status(StatusCode::NOT_FOUND);
    loop {
        if let (true, _) = request.send(context).await {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Return a unique ID
pub fn id(prefix: &str) -> String {
    let uuid = uuid::Uuid::new_v4();
    format!("{prefix}-{uuid}")
}

pub trait HasPushFixture {
    fn push_fixture(&mut self, fixture: FixtureKind);
}

#[async_trait]
pub trait AsyncDeleteById {
    async fn delete_by_id(&self, id: &str);
}

#[derive(Clone)]
pub enum FixtureKind {
    Id(String),
    File(String),
}

impl FixtureKind {
    async fn cleanup(&self, context: &impl AsyncDeleteById) {
        match self {
            FixtureKind::Id(id) => context.delete_by_id(&id).await,
            FixtureKind::File(path) => {
                remove_file(&path).await.unwrap();
            }
        }
    }
}

#[async_trait]
pub trait FileUtility: HasPushFixture {
    async fn create_file(&mut self, path: &str) -> File {
        File::create(path).await.expect("file creation failed");
        self.push_fixture(FixtureKind::File(String::from(path)));
        File::open(path).await.unwrap()
    }
}

pub trait Urlifier {
    fn base_url(&self) -> &Url;
    fn urlify<S: Into<String>>(&self, path: S) -> Url {
        self.base_url().join(&path.into()).unwrap()
    }
}

fn testing_auth() -> AuthConfigArguments {
    AuthConfigArguments {
        disabled: false,
        config: Some("config/auth.yaml".into()),
        clients: Default::default(),
    }
}

fn testing_swagger_ui_oidc() -> SwaggerUiOidcConfig {
    SwaggerUiOidcConfig {
        tls_insecure: false,
        ca_certificates: vec![],
        swagger_ui_oidc_issuer_url: Some(devmode::issuer_url()),
        swagger_ui_oidc_client_id: "frontend".to_string(),
    }
}
