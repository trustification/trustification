pub struct Index {
}

pub enum Error {
    Other
}

impl Index {
    pub fn new() -> Self {
        Self {

        }
    }

    pub async fn query_purl(&self, purl: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }

    pub async fn query_hash(&self, hash: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }
}
