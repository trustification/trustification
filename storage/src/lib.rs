use std::fmt::Display;

use s3::creds::error::CredentialsError;
pub use s3::creds::Credentials;
use s3::error::S3Error;
use s3::Bucket;
pub use s3::Region;

pub struct Storage {
    bucket: Bucket,
    prefix: String,
}

pub struct Config {
    bucket_name: String,
    region: Region,
    credentials: Credentials,
}

impl Config {
    pub fn new_minio_test() -> Self {
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
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal => write!(f, "Internal error"),
            Self::Credentials(e) => write!(f, "{}", e),
            Self::S3(e) => write!(f, "{}", e),
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

const BASE_PATH: &str = "/data/sbom/";

impl Storage {
    pub fn new(config: Config) -> Result<Self, Error> {
        let prefix = format!("{}{}", config.bucket_name, BASE_PATH);
        let bucket = Bucket::new(&config.bucket_name, config.region, config.credentials)?.with_path_style();
        Ok(Self { bucket, prefix })
    }

    pub fn extract_key<'m>(&'m self, key: &'m str) -> Option<&'m str> {
        key.strip_prefix(&self.prefix)
    }

    pub async fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let path = format!("{}{}", BASE_PATH, key);
        self.bucket.put_object(path, value).await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = format!("{}{}", BASE_PATH, key);
        let data = self.bucket.get_object(path).await?;
        Ok(data.to_vec())
    }
}
