use anyhow::Result;
use url::Url;

/// A bombastic HTTP client to publish SBOMS

const SBOM_POST_PATH: &str = "api/v1/sbom";

pub struct BombasticClient {
    bombastic: Url,
    client: reqwest::Client
}

pub struct SbomData {
    signature: Vec<u8>,
    checksum: Vec<u8>,
    content: Vec<u8>
}


impl BombasticClient {
    pub fn new(bombastic: Url) -> BombasticClient {
        let mut bombastic = bombastic.clone();
        bombastic.set_path(SBOM_POST_PATH);

        BombasticClient {
            bombastic,
            client: reqwest::Client::new(),
        }
    }

    pub async fn download_data(&self, address: Url) -> Result<SbomData> {j

        let content = self.client.get(address).send().await.

        SbomData {
            signature: Vec::new(),
            checksum: Vec::new(),
            content: Vec::new(),
        }
    }
}

