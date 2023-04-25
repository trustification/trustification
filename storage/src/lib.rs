pub struct Storage {
}

pub enum Error {
    Other
}

impl Storage {
    pub fn new() -> Self {
        Self {

        }
    }

    pub async fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        todo!()
    }

    pub async fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }
}
