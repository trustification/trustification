use std::path::PathBuf;


pub struct Index {
}

pub enum Error {
    Open,
    Other
}

impl Index {
    pub fn new<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let connection = sqlite::open(path).map_err(|_| Error::Open)?;
        Self {
            connection,
        }
    }

    pub fn new_with_handle(connection: sqlite::Connection) -> Self {
        Self {
            connection
        }
    }

    pub async fn query_purl(&mut self, purl: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }

    pub async fn query_hash(&mut self, hash: &str) -> Result<Vec<u8>, Error> {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn init(conn: &mut sqlite::Connection) {
        let schema = File::open("../schema.sql");
        conn.execute(schema).unwrap();

        let test_data = "INSERT into sboms VALUES (\"purl1\", \"116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70\", \"116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70\")";
        conn.execute(test_data).unwrap();
    }

    #[tokio::test]
    fn test_query() {
        let conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index.query_purl("purl1");
        assert!(result.is_ok());
    }
}
