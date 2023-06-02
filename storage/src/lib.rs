use std::marker::Unpin;
use std::{collections::HashMap, fmt::Display};

use async_stream::try_stream;
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
use tokio_util::io::StreamReader;

pub enum StorageType {
    Minio,
    S3,
}

pub struct Storage {
    bucket: Bucket,
    prefix: String,
    index_prefix: String,
    stype: StorageType,
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
        Storage::new(Config::test(bucket_name, storage_endpoint), StorageType::Minio)?
    } else {
        Storage::new(Config::defaults(bucket_name)?, StorageType::S3)?
    };
    Ok(storage)
}

#[derive(Debug)]
pub enum Error {
    Internal,
    Credentials(CredentialsError),
    S3(S3Error),
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "Internal error"),
            Self::Credentials(e) => write!(f, "{}", e),
            Self::S3(e) => write!(f, "{}", e),
            Self::Io(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

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
    pub fn new(config: Config, stype: StorageType) -> Result<Self, Error> {
        let prefix = format!("{}{}", config.bucket_name, DATA_PATH);
        let index_prefix = format!("{}{}", config.bucket_name, INDEX_PATH);
        let bucket = Bucket::new(&config.bucket_name, config.region, config.credentials)?.with_path_style();
        Ok(Self {
            bucket,
            prefix,
            stype,
            index_prefix,
        })
    }

    pub fn is_index(&self, key: &str) -> bool {
        self.index_prefix == key
    }

    pub fn extract_key<'m>(&'m self, key: &'m str) -> Option<&'m str> {
        key.strip_prefix(&self.prefix)
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
        let mut reader = StreamReader::new(stream);
        let path = format!("{}{}", DATA_PATH, key);
        Ok(bucket
            .put_object_stream_with_content_type(&mut reader, path, content_type)
            .await?)
    }

    // This will load the entire S3 object into memory
    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        let data = self.bucket.get_object(path).await?;
        Ok(data.to_vec())
    }

    // Returns a tuple of content-type and byte stream
    pub async fn get_stream(
        &self,
        key: &str,
    ) -> Result<(Option<String>, impl Stream<Item = Result<Bytes, Error>>), Error> {
        let path = format!("{}{}", DATA_PATH, key);
        let (head, _status) = self.bucket.head_object(&path).await?;
        let mut s = self.bucket.get_object_stream(&path).await?;
        let stream = try_stream! {
            while let Some(chunk) = s.bytes().next().await {
                yield chunk;
            }
        };
        Ok((head.content_type, stream))
    }

    pub async fn get_metadata(&self, key: &str) -> Result<HashMap<String, String>, Error> {
        let path = format!("{}{}", DATA_PATH, key);
        let (head, _status) = self.bucket.head_object(&path).await?;
        Ok(head.metadata.unwrap_or(HashMap::new()))
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
        match self.stype {
            StorageType::Minio => Ok(serde_json::from_slice::<MinioEvent>(event)
                .map_err(|_e| Error::Internal)?
                .try_into()?),
            StorageType::S3 => Ok(serde_json::from_slice::<S3Event>(event)
                .map_err(|_e| Error::Internal)?
                .try_into()?),
        }
    }
}

#[derive(Debug)]
pub struct StorageEvent {
    pub event_type: EventType,
    pub key: String,
}

const MINIO_PUT_EVENT: &str = "s3:ObjectCreated:Put";
const MINIO_DELETE_EVENT: &str = "s3:ObjectRemoved:Delete";

impl TryFrom<MinioEvent> for StorageEvent {
    type Error = Error;
    fn try_from(minio: MinioEvent) -> Result<Self, Self::Error> {
        let event_type = match minio.event_name.as_ref() {
            MINIO_PUT_EVENT => Ok(EventType::Put),
            MINIO_DELETE_EVENT => Ok(EventType::Delete),
            _ => Err(Error::Internal),
        }?;
        Ok(Self {
            event_type,
            key: minio.key,
        })
    }
}

const S3_PUT_EVENT: &str = "ObjectCreated:Put";
const S3_DELETE_EVENT: &str = "ObjectRemoved:Delete";

impl TryFrom<S3Event> for StorageEvent {
    type Error = Error;
    fn try_from(s3: S3Event) -> Result<Self, Self::Error> {
        let first = s3.records.first().ok_or(Error::Internal)?;
        let event_type = match first.event_name.as_ref() {
            S3_PUT_EVENT => Ok(EventType::Put),
            S3_DELETE_EVENT => Ok(EventType::Delete),
            _ => Err(Error::Internal),
        }?;
        Ok(StorageEvent {
            event_type,
            key: first.s3.object.key.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EventType {
    Put,
    Delete,
}

#[derive(Deserialize, Debug)]
struct MinioEvent {
    #[serde(rename = "EventName")]
    event_name: String,
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Deserialize, Debug)]
pub struct S3Event {
    #[serde(rename = "Records")]
    pub records: Vec<S3Record>,
}

#[derive(Deserialize, Debug)]
pub struct S3Record {
    #[serde(rename = "s3")]
    s3: S3Data,
    #[serde(rename = "eventName")]
    pub event_name: String,
}

#[derive(Deserialize, Debug)]
pub struct S3Data {
    #[serde(rename = "object")]
    pub object: S3Object,
}

#[derive(Deserialize, Debug)]
pub struct S3Object {
    #[serde(rename = "key")]
    pub key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_decode() {
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
                "key": "bombastic/data/mysbom11",
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
        let decoded = serde_json::from_str::<S3Event>(event).unwrap();
        let converted: StorageEvent = decoded.try_into().unwrap();

        assert_eq!(converted.event_type, EventType::Put);
        assert_eq!(converted.key, "bombastic/data/mysbom11");

        let storage = Storage::new(Config::test("bombastic", None), StorageType::S3).unwrap();
        let decoded = storage.decode_event(event.as_bytes()).unwrap();
        assert_eq!(decoded.event_type, EventType::Put);
        assert_eq!(decoded.key, "bombastic/data/mysbom11");
    }
}
