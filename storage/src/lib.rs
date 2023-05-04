use s3::creds::error::CredentialsError;
use s3::error::S3Error;
use s3::Bucket;
use std::fmt::Display;

pub use s3::creds::Credentials;
pub use s3::Region;

pub struct Storage {
    bucket: Bucket,
}

pub struct Config {
    bucket_name: String,
    region: Region,
    credentials: Credentials,
}

impl Config {
    pub fn new_minio_test() -> Self {
        Config {
            bucket_name: "test-rust-s3".to_string(),
            region: Region::Custom {
                region: "eu-central-1".to_owned(),
                endpoint: "http://localhost:9000".to_owned(),
            },
            credentials: Credentials::default().unwrap(),
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

const BASE_PATH: &str = "/bombastic/sbom";

impl Storage {
    pub fn new(config: Config) -> Result<Self, Error> {
        let bucket =
            Bucket::new(&config.bucket_name, config.region, config.credentials)?.with_path_style();
        Ok(Self { bucket })
    }

    pub async fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let path = format!("{}/{}", BASE_PATH, key);
        self.bucket.put_object(path, value).await?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = format!("{}/{}", BASE_PATH, key);
        let data = self.bucket.get_object(path).await?;
        Ok(data.to_vec())
    }
}
