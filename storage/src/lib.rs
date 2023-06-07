mod stream;

use async_compression::tokio::bufread::ZstdEncoder;
use async_stream::stream;
use bytes::{Buf, Bytes};
use futures::future::ok;
use futures::stream::once;
use futures::{Stream, StreamExt};
use mime::Mime;
use s3::creds::error::CredentialsError;
pub use s3::creds::Credentials;
use s3::error::S3Error;
use s3::Bucket;
pub use s3::Region;
use serde::Deserialize;
use std::marker::Unpin;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

pub struct Storage {
    bucket: Bucket,
}

pub struct Config {
    bucket_name: String,
    region: Region,
    credentials: Credentials,
}

impl Config {
    pub fn defaults(bucket_name: &str) -> Result<Self, anyhow::Error> {
        Ok(Config {
            bucket_name: bucket_name.to_string(),
            region: Region::from_default_env()?,
            credentials: Credentials::from_env()?,
        })
    }

    pub fn test(bucket_name: &str, endpoint: Option<String>) -> Self {
        Config {
            bucket_name: bucket_name.to_string(),
            region: Region::Custom {
                region: "eu-central-1".to_owned(),
                endpoint: endpoint.unwrap_or("http://localhost:9000".to_owned()),
            },
            credentials: Credentials {
                access_key: Some("admin".into()),
                secret_key: Some("password".into()),
                security_token: None,
                session_token: None,
                expiration: None,
            },
        }
    }
}

pub fn create(bucket_name: &str, devmode: bool, storage_endpoint: Option<String>) -> Result<Storage, anyhow::Error> {
    let storage = if devmode {
        Storage::new(Config::test(bucket_name, storage_endpoint))?
    } else {
        Storage::new(Config::defaults(bucket_name)?)?
    };
    Ok(storage)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("internal storage error")]
    Internal,
    #[error("error with credentials")]
    Credentials(CredentialsError),
    #[error("error with s3 backend {0}")]
    S3(S3Error),
    #[error("I/O error {0}")]
    Io(std::io::Error),
    #[error("invalid storage key {0}")]
    InvalidKey(String),
}

impl From<CredentialsError> for Error {
    fn from(e: CredentialsError) -> Self {
        Self::Credentials(e)
    }
}

impl From<S3Error> for Error {
    fn from(e: S3Error) -> Self {
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

const DATA_PATH: &str = "/data/";
const INDEX_PATH: &str = "/index";
const VERSION_HEADER: &str = "x-amz-meta-version";

const VERSION: u32 = 1;

impl Storage {
    pub fn new(config: Config) -> Result<Self, Error> {
        let bucket = Bucket::new(&config.bucket_name, config.region, config.credentials)?.with_path_style();
        Ok(Self { bucket })
    }

    pub fn is_index(&self, key: &str) -> bool {
        format!("/{}", key) == INDEX_PATH
    }

    pub async fn put_slice<'a>(&self, key: &'a str, content_type: Mime, data: &'a [u8]) -> Result<u16, Error> {
        self.put_stream(key, content_type, &mut once(ok::<_, std::io::Error>(data)))
            .await
    }

    pub async fn put_stream<S, B, E>(&self, key: &str, content_type: Mime, stream: &mut S) -> Result<u16, Error>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: Buf,
        E: Into<std::io::Error>,
    {
        let mut headers = http::HeaderMap::new();
        headers.insert(VERSION_HEADER, VERSION.into());
        let bucket = self.bucket.with_extra_headers(headers);
        let path = format!("{}{}", DATA_PATH, key);

        // Compress json using zstd
        // TODO: fix lifetimes to put this logic in stream module.
        let (mut rdr, ty): (Box<dyn AsyncRead + Unpin>, &str) = if content_type == mime::APPLICATION_JSON {
            (Box::new(ZstdEncoder::new(StreamReader::new(stream))), stream::MIME_ZSTD)
        } else {
            (Box::new(StreamReader::new(stream)), content_type.as_ref())
        };
        Ok(bucket.put_object_stream_with_content_type(&mut rdr, path, ty).await?)
    }

    // This will load the entire S3 object into memory
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        self.get_object(&path).await
    }

    // Returns a tuple of content-type and byte stream, and will
    // uncompress the mime types stream::decode(...) recognizes
    pub async fn get_stream(
        &self,
        key: &str,
    ) -> Result<(Option<String>, impl Stream<Item = Result<Bytes, Error>>), Error> {
        let path = format!("{}{}", DATA_PATH, key);
        self.get_object_stream(&path).await
    }

    // Get the data associated with an event record.
    // This will load the entire S3 object into memory
    pub async fn get_for_event(&self, record: &Record) -> Result<Vec<u8>, Error> {
        // Record keys are URL encoded
        if let Ok(decoded) = urlencoding::decode(record.key()) {
            self.get_object(&decoded).await
        } else {
            Err(Error::InvalidKey(record.key().to_string()))
        }
    }

    pub async fn put_index(&self, index: &[u8]) -> Result<(), Error> {
        self.bucket.put_object(INDEX_PATH, index).await?;
        Ok(())
    }

    pub async fn get_index(&self) -> Result<Vec<u8>, Error> {
        let data = self.bucket.get_object(INDEX_PATH).await?;
        Ok(data.to_vec())
    }

    pub fn decode_event(&self, event: &[u8]) -> Result<StorageEvent, Error> {
        serde_json::from_slice::<StorageEvent>(event).map_err(|_e| Error::Internal)
    }

    // Expects the actual S3 path
    // This will load the entire S3 object into memory
    async fn get_object(&self, path: &str) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![];
        let (_, stream) = self.get_object_stream(path).await?;
        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?)
        }
        Ok(bytes)
    }

    // Expects the actual S3 path
    async fn get_object_stream(
        &self,
        path: &str,
    ) -> Result<(Option<String>, impl Stream<Item = Result<Bytes, Error>>), Error> {
        let (head, _status) = self.bucket.head_object(path).await?;
        let mut s = self.bucket.get_object_stream(path).await?;
        let stream = stream! {
            while let Some(chunk) = s.bytes().next().await {
                yield chunk.map_err(Error::S3);
            }
        };
        Ok(stream::decode(head.content_type, stream.boxed()))
    }
}

const PUT_EVENT: &str = "ObjectCreated:Put";
const DELETE_EVENT: &str = "ObjectRemoved:Delete";

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
        if self.event_name.ends_with(PUT_EVENT) {
            EventType::Put
        } else if self.event_name.ends_with(DELETE_EVENT) {
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

#[derive(Deserialize, Debug)]
pub struct S3Data {
    #[serde(rename = "object")]
    object: S3Object,
    #[serde(rename = "bucket")]
    bucket: S3Bucket,
}

#[derive(Deserialize, Debug)]
pub struct S3Object {
    #[serde(rename = "key")]
    key: String,
}

#[derive(Deserialize, Debug)]
pub struct S3Bucket {
    #[serde(rename = "name")]
    name: String,
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
}
