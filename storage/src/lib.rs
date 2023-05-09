use std::fmt::Display;

use s3::creds::error::CredentialsError;
pub use s3::creds::Credentials;
use s3::error::S3Error;
use s3::Bucket;
pub use s3::Region;
use serde::{Deserialize, Serialize};

pub struct Storage {
    bucket: Bucket,
    prefix: String,
    index_prefix: String,
}

pub struct Config {
    bucket_name: String,
    region: Region,
    credentials: Credentials,
}

impl Config {
    pub fn defaults() -> Result<Self, anyhow::Error> {
        Ok(Config {
            bucket_name: "bombastic".to_string(),
            region: Region::from_default_env()?,
            credentials: Credentials::from_env()?,
        })
    }

    pub fn minio_test() -> Self {
        Config {
            bucket_name: "bombastic".to_string(),
            region: Region::Custom {
                region: "eu-central-1".to_owned(),
                endpoint: "http://localhost:9000".to_owned(),
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

#[derive(Debug)]
pub enum Error {
    Internal,
    Credentials(CredentialsError),
    S3(S3Error),
    Io(std::io::Error),
    Codec(bincode::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "Internal error"),
            Self::Credentials(e) => write!(f, "{}", e),
            Self::S3(e) => write!(f, "{}", e),
            Self::Io(e) => write!(f, "{}", e),
            Self::Codec(e) => write!(f, "{}", e),
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

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Self::Codec(e)
    }
}

const SBOM_PATH: &str = "/data/sbom/";
const INDEX_PATH: &str = "/index.sqlite";

const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct Object<'a> {
    version: u32,
    pub purl: &'a str,
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl<'a> Object<'a> {
    pub fn new(purl: &'a str, data: &'a [u8], compressed: bool) -> Self {
        Self {
            version: VERSION,
            purl,
            data: data.to_vec(),
            compressed,
        }
    }

    fn to_owned(self) -> OwnedObject {
        OwnedObject {
            version: self.version,
            purl: self.purl.to_string(),
            compressed: self.compressed,
            data: self.data,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OwnedObject {
    version: u32,
    pub purl: String,
    pub compressed: bool,
    pub data: Vec<u8>,
}

impl Storage {
    pub fn new(config: Config) -> Result<Self, Error> {
        let prefix = format!("{}{}", config.bucket_name, SBOM_PATH);
        let index_prefix = format!("{}{}", config.bucket_name, INDEX_PATH);
        let bucket = Bucket::new(&config.bucket_name, config.region, config.credentials)?.with_path_style();
        Ok(Self {
            bucket,
            prefix,
            index_prefix,
        })
    }

    pub fn is_index(&self, key: &str) -> bool {
        self.index_prefix == key
    }

    pub fn extract_key<'m>(&'m self, key: &'m str) -> Option<&'m str> {
        key.strip_prefix(&self.prefix)
    }

    pub async fn put(&self, key: &str, value: Object<'_>) -> Result<(), Error> {
        let path = format!("{}{}", SBOM_PATH, key);
        let value = bincode::serialize(&value)?;
        self.bucket.put_object(path, &value).await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<OwnedObject, Error> {
        let path = format!("{}{}", SBOM_PATH, key);
        let data = self.bucket.get_object(path).await?;
        let value: Object<'_> = bincode::deserialize(&data.as_slice())?;
        Ok(value.to_owned())
    }

    pub async fn put_index(&self, index: &[u8]) -> Result<(), Error> {
        self.bucket.put_object(INDEX_PATH, index).await?;
        Ok(())
    }

    pub async fn get_index(&self) -> Result<Vec<u8>, Error> {
        let data = self.bucket.get_object(INDEX_PATH).await?;
        Ok(data.to_vec())
    }
}
