mod stream;
pub mod validator;

use std::borrow::Cow;

use async_stream::try_stream;
use bytes::Bytes;
use futures::pin_mut;
use futures::{future::ok, stream::once, Stream, StreamExt};
use hide::Hide;
use http::{header::CONTENT_ENCODING, HeaderValue, StatusCode};
use prometheus::{
    histogram_opts, opts, register_histogram_with_registry, register_int_counter_with_registry, Histogram, IntCounter,
    Registry,
};
use s3::{creds::error::CredentialsError, error::S3Error, Bucket};
pub use s3::{creds::Credentials, Region};
use serde::Deserialize;
use validator::Validator;

pub struct Storage {
    bucket: Bucket,
    metrics: Metrics,
    validator: Validator,
}

#[derive(Clone)]
struct Metrics {
    puts_failed_total: IntCounter,
    puts_total: IntCounter,
    index_puts_total: IntCounter,
    // NOTE: We cannot observe the get latency of streamed gets from within storage
    gets_total: IntCounter,
    gets_failed_total: IntCounter,

    deletes_total: IntCounter,
    deletes_failed_total: IntCounter,

    put_latency_seconds: Histogram,
    get_latency_seconds: Histogram,
}

impl Metrics {
    fn register(registry: &Registry, prefix: String) -> Result<Self, Error> {
        let prefix = if prefix.is_empty() {
            prefix
        } else {
            format!("{prefix}_")
        };
        let puts_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_object_puts_total"),
                "Total number of put operations"
            ),
            registry
        )?;

        let index_puts_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_index_puts_total"),
                "Total number of put operations for index"
            ),
            registry
        )?;

        let gets_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_object_gets_total"),
                "Total number of get operations"
            ),
            registry
        )?;

        let deletes_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_object_deletes_total"),
                "Total number of delete operations"
            ),
            registry
        )?;

        let puts_failed_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_puts_failed_total"),
                "Total number of failed put operations"
            ),
            registry
        )?;

        let gets_failed_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_gets_failed_total"),
                "Total number of failed get operations"
            ),
            registry
        )?;

        let deletes_failed_total = register_int_counter_with_registry!(
            opts!(
                format!("{prefix}storage_deletes_failed_total"),
                "Total number of failed delete operations"
            ),
            registry
        )?;

        let put_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                format!("{prefix}storage_put_latency_seconds"),
                "Put latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        let get_latency_seconds = register_histogram_with_registry!(
            histogram_opts!(
                format!("{prefix}storage_get_latency_seconds"),
                "Get latency",
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ),
            registry
        )?;

        Ok(Self {
            puts_total,
            index_puts_total,
            gets_total,
            deletes_total,
            puts_failed_total,
            gets_failed_total,
            deletes_failed_total,
            put_latency_seconds,
            get_latency_seconds,
        })
    }
}

#[derive(Clone, Debug, Default, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE", next_help_heading = "Storage")]
pub struct StorageConfig {
    /// Bucket name to use for storing data and index
    #[arg(env = "STORAGE_BUCKET", long = "storage-bucket")]
    pub bucket: Option<String>,

    /// Storage region to use
    #[arg(env = "STORAGE_REGION", long = "storage-region")]
    pub region: Option<Region>,

    /// Storage endpoint to use
    #[arg(env = "STORAGE_ENDPOINT", long = "storage-endpoint")]
    pub endpoint: Option<String>,

    /// Access key for using storage
    #[arg(env = "STORAGE_ACCESS_KEY", long = "storage-access-key")]
    pub access_key: Option<Hide<String>>,

    /// Secret key for using storage
    #[arg(env = "STORAGE_SECRET_KEY", long = "storage-secret-key")]
    pub secret_key: Option<Hide<String>>,

    #[arg(long = "validate", default_value_t = true)]
    pub validate: bool,
}

impl TryInto<Bucket> for StorageConfig {
    type Error = Error;
    fn try_into(self) -> Result<Bucket, Error> {
        let access_key = self.access_key.ok_or(Error::MissingParameter("access-key".into()))?;
        let secret_key = self.secret_key.ok_or(Error::MissingParameter("secret-key".into()))?;
        let credentials = Credentials {
            access_key: Some(access_key.0),
            secret_key: Some(secret_key.0),
            security_token: None,
            session_token: None,
            expiration: None,
        };
        let mut region = self.region.ok_or(Error::MissingParameter("region".into()))?;
        if let Some(endpoint) = self.endpoint {
            // the only way to set a custom endpoint is via a custom region
            region = Region::Custom {
                region: region.to_string(),
                endpoint,
            }
        }
        let bucket = self.bucket.ok_or(Error::MissingParameter("bucket".into()))?;
        let bucket = Bucket::new(&bucket, region, credentials)?.with_path_style();
        Ok(bucket)
    }
}

impl StorageConfig {
    pub fn process(&self, default_bucket: &str, devmode: bool) -> StorageConfig {
        let mut result = self.clone();
        if devmode {
            if self.access_key.is_none() {
                result.access_key = Some("admin".into());
            }

            if self.secret_key.is_none() {
                result.secret_key = Some("password".into());
            }

            if self.bucket.is_none() {
                result.bucket = Some(default_bucket.to_string());
            }

            if self.region.is_none() {
                result.region = Some(Region::Custom {
                    region: Region::EuCentral1.to_string(),
                    endpoint: self.endpoint.clone().unwrap_or("http://localhost:9000".into()),
                });
            }

            if self.endpoint.is_none() {
                result.endpoint = Some("http://localhost:9000".into());
            }

            log::info!("Update config to {:#?}", result);

            result
        } else {
            result
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("internal storage error")]
    Internal,
    #[error("object not found")]
    NotFound,
    #[error("missing configuration parameter {0}")]
    MissingParameter(String),
    #[error("error with credentials")]
    Credentials(CredentialsError),
    #[error("error with s3 backend {0}")]
    S3(S3Error),
    #[error("I/O error {0}")]
    Io(std::io::Error),
    #[error("invalid storage key {0}")]
    InvalidKey(String),
    #[error("invalid storage content")]
    InvalidContent,
    #[error("unexpected encoding {0}")]
    Encoding(String),
    #[error("Prometheus error {0}")]
    Prometheus(prometheus::Error),
}

impl From<CredentialsError> for Error {
    fn from(e: CredentialsError) -> Self {
        Self::Credentials(e)
    }
}

impl From<S3Error> for Error {
    fn from(e: S3Error) -> Self {
        if let S3Error::HttpFailWithBody(status, _) = e {
            if status == 404 {
                return Self::NotFound;
            }
        }
        Self::S3(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        match e {
            Error::Io(e) => e,
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}

impl From<http::header::InvalidHeaderName> for Error {
    fn from(_: http::header::InvalidHeaderName) -> Self {
        Self::Internal
    }
}

impl From<http::header::InvalidHeaderValue> for Error {
    fn from(_: http::header::InvalidHeaderValue) -> Self {
        Self::Internal
    }
}

impl From<prometheus::Error> for Error {
    fn from(e: prometheus::Error) -> Self {
        Self::Prometheus(e)
    }
}

const DATA_PATH: &str = "/data/";
const INDEX_PATH: &str = "/index";
const VERSION_HEADER: &str = "x-amz-meta-version";
const VERSION: u32 = 1;
const DEFAULT_ENCODING: &str = "zstd";

pub struct Head {
    pub status: StatusCode,
    pub content_encoding: Option<String>,
}

impl Storage {
    pub fn new(config: StorageConfig, v: Validator, registry: &Registry) -> Result<Self, Error> {
        let prefix = v.to_string();
        let validator = if config.validate { v } else { Validator::None };
        let bucket = config.try_into()?;
        Ok(Self {
            bucket,
            metrics: Metrics::register(registry, prefix)?,
            validator,
        })
    }

    pub fn is_index(&self, path: &str) -> bool {
        S3Path::from_path(path).path.starts_with(INDEX_PATH)
    }

    pub async fn put_stream<'a>(
        &self,
        key: &'a str,
        content_type: &'a str,
        encoding: Option<&str>,
        data: impl Stream<Item = Result<Bytes, Error>>,
    ) -> Result<usize, Error> {
        self.metrics.puts_total.inc();
        let put_start = self.metrics.put_latency_seconds.start_timer();
        let mut headers = http::HeaderMap::new();
        headers.insert(VERSION_HEADER, VERSION.into());
        headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_str(encoding.unwrap_or(DEFAULT_ENCODING)).unwrap(),
        );
        let bucket = self.bucket.with_extra_headers(headers);

        let data = self.validator.validate(encoding, Box::pin(data)).await?;
        let mut rdr = stream::encoded_reader(DEFAULT_ENCODING, encoding, data)?;
        let path = format!("{}{}", DATA_PATH, key);

        let len = bucket
            .put_object_stream_with_content_type(&mut rdr, path, content_type)
            .await
            .map_err(|e| {
                self.metrics.puts_failed_total.inc();
                e
            })?
            .uploaded_bytes();
        put_start.observe_duration();
        Ok(len)
    }

    pub async fn put_json_slice<'a>(&self, key: &'a str, json: &'a [u8]) -> Result<usize, Error> {
        let stream = once(ok::<_, Error>(Bytes::copy_from_slice(json)));
        self.put_stream(key, "application/json", None, stream).await
    }

    pub async fn get_head(&self, key: &str) -> Result<Head, Error> {
        let path: S3Path = S3Path::from_key(key);
        let (head, status) = self.bucket.head_object(&path.path).await?;
        Ok(Head {
            status: StatusCode::from_u16(status).map_err(|_| Error::Internal)?,
            content_encoding: head.content_encoding,
        })
    }

    pub fn key_from_event(record: &Record) -> Result<(Cow<str>, String), Error> {
        if let Ok(decoded) = urlencoding::decode(record.key()) {
            let key = S3Path::from_path(&decoded).key().to_string();
            Ok((decoded, key))
        } else {
            Err(Error::InvalidKey(record.key().to_string()))
        }
    }

    // Get the data associated with an event record.
    // This will load the entire S3 object into memory
    pub async fn get_for_event(&self, record: &Record, decode: bool) -> Result<S3Result, Error> {
        // Record keys are URL encoded
        if let Ok((decoded, key)) = Self::key_from_event(record) {
            if decode {
                let data = self.get_decoded_object(&key).await?;
                Ok(S3Result {
                    key,
                    data,
                    encoding: None,
                })
            } else {
                let (head, _status) = self.bucket.head_object(&decoded).await?;
                let data = self.get_encoded_object(&key).await?;
                Ok(S3Result {
                    key,
                    data,
                    encoding: head.content_encoding,
                })
            }
        } else {
            Err(Error::InvalidKey(record.key().to_string()))
        }
    }

    pub fn list_objects_from(
        &self,
        mut continuation_token: ContinuationToken,
    ) -> impl Stream<Item = Result<(String, Vec<u8>), (Error, ContinuationToken)>> + '_ {
        let prefix = DATA_PATH[1..].to_string();

        try_stream! {
            loop {
                let (result, _) = self.bucket.list_page(prefix.clone(), None, continuation_token.0.clone(), None, None).await.map_err(|e| (Error::S3(e), continuation_token.clone()))?;
                let next_continuation_token = result.next_continuation_token.clone();

                for obj in result.contents {
                    let key = S3Path::from_path(&obj.key).key().to_string();
                    let o = self.get_decoded_object(&key).await.map_err(|e| (e, continuation_token.clone()))?;
                    yield (key, o);
                }

                if next_continuation_token.is_none() {
                    break;
                } else {
                    continuation_token = ContinuationToken(next_continuation_token);
                }
            }
        }
    }

    pub async fn put_index(&self, name: &str, index: &[u8]) -> Result<(), Error> {
        let index_path = format!("{}/{}", INDEX_PATH, name);
        self.bucket.put_object(index_path, index).await?;
        self.metrics.index_puts_total.inc();
        Ok(())
    }

    pub async fn get_index(&self, name: &str) -> Result<Vec<u8>, Error> {
        let index_path = format!("{}/{}", INDEX_PATH, name);
        let data = self.bucket.get_object(index_path).await?;
        Ok(data.to_vec())
    }

    pub fn decode_event(&self, event: &[u8]) -> Result<StorageEvent, Error> {
        serde_json::from_slice::<StorageEvent>(event).map_err(|_e| Error::Internal)
    }

    pub async fn get_decoded_stream(&self, key: &str) -> Result<impl Stream<Item = Result<Bytes, Error>>, Error> {
        let path: S3Path = S3Path::from_key(key);
        self.metrics.gets_total.inc();
        let res = {
            let (head, _status) = self.bucket.head_object(&path.path).await?;
            let stream = self.get_encoded_stream(key).await?;
            stream::decode(head.content_encoding.as_deref(), Box::pin(stream))
        };
        if res.is_err() {
            self.metrics.gets_failed_total.inc();
        }
        res
    }

    pub async fn get_encoded_stream(&self, key: &str) -> Result<impl Stream<Item = Result<Bytes, Error>>, Error> {
        let path: S3Path = S3Path::from_key(key);
        let mut s = self.bucket.get_object_stream(&path.path).await?;
        Ok(try_stream! { while let Some(chunk) = s.bytes().next().await { yield chunk?; }})
    }

    pub async fn delete(&self, key: &str) -> Result<u16, Error> {
        self.metrics.deletes_total.inc();
        let path = format!("{}{}", DATA_PATH, key);
        let res = self
            .bucket
            .delete_object(path)
            .await
            .map(|r| r.status_code())
            .map_err(|e| {
                self.metrics.deletes_failed_total.inc();
                e
            })?;
        Ok(res)
    }

    // Deletes all data in the bucket (except index)
    pub async fn delete_all(&self) -> Result<(), Error> {
        let results = self.bucket.list(DATA_PATH[1..].to_string(), None).await?;
        for result in results {
            for obj in result.contents {
                self.metrics.deletes_total.inc();
                self.bucket
                    .delete_object(obj.key)
                    .await
                    .map(|r| r.status_code())
                    .map_err(|e| {
                        self.metrics.deletes_failed_total.inc();
                        e
                    })?;
            }
        }
        Ok(())
    }

    // private helper functions

    // This will load the entire S3 object into memory
    async fn get_decoded_object(&self, key: &str) -> Result<Vec<u8>, Error> {
        self.get_object_from_stream(self.get_decoded_stream(key).await?).await
    }

    // This will load the encoded S3 object into memory
    async fn get_encoded_object(&self, key: &str) -> Result<Vec<u8>, Error> {
        self.get_object_from_stream(self.get_encoded_stream(key).await?).await
    }

    async fn get_object_from_stream(&self, stream: impl Stream<Item = Result<Bytes, Error>>) -> Result<Vec<u8>, Error> {
        let get_start = self.metrics.get_latency_seconds.start_timer();
        let mut bytes = vec![];
        pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?)
        }
        get_start.observe_duration();
        Ok(bytes)
    }
}

#[derive(Clone, Default)]
pub struct ContinuationToken(Option<String>);

const PUT_EVENT: &str = "ObjectCreated:Put";
const MULTIPART_PUT_EVENT: &str = "ObjectCreated:CompleteMultipartUpload";
const DELETE_EVENT: &str = "ObjectRemoved:Delete";
const DELETE_MARKER_EVENT: &str = "ObjectRemoved:DeleteMarkerCreated";

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EventType {
    Put,
    Delete,
    Other,
}

#[derive(Deserialize, Debug)]
pub struct StorageEvent {
    #[serde(rename = "Records")]
    pub records: Vec<Record>,
}

#[derive(Deserialize, Debug)]
pub struct Record {
    #[serde(rename = "s3")]
    s3: S3Data,
    #[serde(rename = "eventName")]
    event_name: String,
}

impl Record {
    pub fn event_type(&self) -> EventType {
        if self.event_name.ends_with(PUT_EVENT) || self.event_name.ends_with(MULTIPART_PUT_EVENT) {
            EventType::Put
        } else if self.event_name.ends_with(DELETE_EVENT) || self.event_name.ends_with(DELETE_MARKER_EVENT) {
            EventType::Delete
        } else {
            EventType::Other
        }
    }

    pub fn key(&self) -> &str {
        &self.s3.object.key
    }

    pub fn bucket(&self) -> &str {
        &self.s3.bucket.name
    }
}

#[derive(Clone, Debug)]
struct S3Path {
    path: String,
}

impl S3Path {
    // Absolute path
    pub fn from_path(path: &str) -> S3Path {
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        S3Path { path }
    }
    // Relative to base
    pub fn from_key(key: &str) -> S3Path {
        S3Path {
            path: format!("{}{}", DATA_PATH, key),
        }
    }
    // Key without prefix
    pub fn key(&self) -> &str {
        self.path.strip_prefix(DATA_PATH).unwrap_or(&self.path)
    }
}

#[derive(Deserialize, Debug)]
struct S3Data {
    #[serde(rename = "object")]
    object: S3Object,
    #[serde(rename = "bucket")]
    bucket: S3Bucket,
}

#[derive(Deserialize, Debug)]
struct S3Object {
    #[serde(rename = "key")]
    key: String,
}

#[derive(Deserialize, Debug)]
struct S3Bucket {
    #[serde(rename = "name")]
    name: String,
}

pub struct S3Result {
    pub key: String,
    pub data: Vec<u8>,
    pub encoding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_decode() {
        let event = r#"{
        "Records": [
            {
            "awsRegion": "eu-west-1",
            "eventName": "ObjectCreated:Put",
            "eventSource": "aws:s3",
            "eventTime": "2023-05-11T13:25:03.104Z",
            "eventVersion": "2.1",
            "requestParameters": {
                "sourceIPAddress": "10.0.220.140"
            },
            "responseElements": {
                "x-amz-id-2": "PmiHPIpmhpjmmijsu6xXEtk9E2NEK29FBDtZcvGU1jgt7EFFopTzWFPyv/nZwR60Qx5nCvPvVbXKV0wkg87aiSvbgRaIgK8x",
                "x-amz-request-id": "X3ZPARGNVP97GNFA"
            },
            "s3": {
                "bucket": {
                    "arn": "arn:aws:s3:::bombastic",
                    "name": "bombastic",
                    "ownerIdentity": {
                        "principalId": "A269W3T43498LN"
                    }
                },
                "configurationId": "stored",
                "object": {
                    "eTag": "7e1f5bce30a48e7618d8d5619d51a20b",
                    "key": "data/mysbom11",
                    "sequencer": "00645CECAF0EE0E7F8",
                    "size": 49312
                },
                "s3SchemaVersion": "1.0"
            },
            "userIdentity": {
                "principalId": "AWS:AIDAUA4TFOLTSNJ5R5SJW"
            }
            }
        ]
        }"#;

        let decoded = serde_json::from_str::<StorageEvent>(event).unwrap();

        assert_eq!(1, decoded.records.len());
        let decoded = &decoded.records[0];
        assert_eq!(decoded.event_type(), EventType::Put);
        assert_eq!(decoded.key(), "data/mysbom11");
        assert_eq!(decoded.bucket(), "bombastic");
    }

    #[test]
    fn test_minio_decode() {
        let event = r#"{"EventName":"s3:ObjectCreated:Put","Key":"vexination/index","Records":[{"eventVersion":"2.0","eventSource":"minio:s3","awsRegion":"","eventTime":"2023-06-05T11:04:06.851Z","eventName":"s3:ObjectCreated:Put","userIdentity":{"principalId":"admin"},"requestParameters":{"principalId":"admin","region":"","sourceIPAddress":"10.89.1.9"},"responseElements":{"content-length":"0","x-amz-id-2":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","x-amz-request-id":"1765BE755F95378E","x-minio-deployment-id":"7637fbd9-a700-4918-bc9d-f7929adf0d8f","x-minio-origin-endpoint":"http://10.89.1.9:9000"},"s3":{"s3SchemaVersion":"1.0","configurationId":"Config","bucket":{"name":"vexination","ownerIdentity":{"principalId":"admin"},"arn":"arn:aws:s3:::vexination"},"object":{"key":"index","size":2851,"eTag":"8aebf225551d1a9c71914a91bf36c7e3","contentType":"application/octet-stream","userMetadata":{"content-type":"application/octet-stream"},"sequencer":"1765BE756000DEDE"}},"source":{"host":"10.89.1.9","port":"","userAgent":""}}]}"#;
        let decoded = serde_json::from_str::<StorageEvent>(event).unwrap();

        assert_eq!(1, decoded.records.len());
        let decoded = &decoded.records[0];
        assert_eq!(decoded.event_type(), EventType::Put);
        assert_eq!(decoded.key(), "index");
        assert_eq!(decoded.bucket(), "vexination");
    }

    #[test]
    fn test_s3_path_keys() {
        let p = S3Path::from_key("FOO");
        assert_eq!(p.key(), "FOO");

        let p = S3Path::from_path("/data/FOO");
        assert_eq!(p.key(), "FOO");

        let p = S3Path::from_path("data/FOO");
        assert_eq!(p.key(), "FOO");

        let p = S3Path::from_path("/data/foo/BAR");
        assert_eq!(p.key(), "foo/BAR");
    }
}
