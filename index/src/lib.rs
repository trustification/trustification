use std::path::Path;


pub struct Index {
    connection: sqlite::Connection,
}

#[derive(Debug)]
pub enum Error {
    Open,
    Internal,
    NotFound,
}

impl Index {
    pub fn new<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let connection = sqlite::open(path).map_err(|_| Error::Open)?;
        Ok(Self {
            connection,
        })
    }

    pub fn new_with_handle(connection: sqlite::Connection) -> Self {
        Self {
            connection
        }
    }

    pub async fn query_purl(&mut self, purl: &str) -> Result<String, Error> {
        const QUERY_PURL: &str = "SELECT obj FROM sboms WHERE purl=?";
        let mut statement = self.connection.prepare(QUERY_PURL)?;
        statement.bind((1, purl))?;

        // PURL is unique so produces only 1 hit
        if let Ok(sqlite::State::Row) = statement.next() {
            Ok(statement.read::<String, _>("obj")?)
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn query_sha256(&mut self, hash: &str) -> Result<String, Error> {
        const QUERY_PURL: &str = "SELECT obj FROM sboms WHERE sha256=?";
        let mut statement = self.connection.prepare(QUERY_PURL)?;
        statement.bind((1, hash))?;

        // SHA256 is unique so produces only 1 hit
        if let Ok(sqlite::State::Row) = statement.next() {
            Ok(statement.read::<String, _>("obj")?)
        } else {
            Err(Error::NotFound)
        }
    }
}

impl From<sqlite::Error> for Error {
    fn from(_e: sqlite::Error) -> Self {
        Self::Internal
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn init(conn: &mut sqlite::Connection) {
        let schema = std::fs::read_to_string("schema.sql").unwrap();
        println!("Read schema: {:?}", schema.trim());
        conn.execute(schema.trim()).unwrap();

        let test_data = std::fs::read_to_string("testdata.sql").unwrap();
        conn.execute(test_data).unwrap();
    }

    #[tokio::test]
    async fn test_query_purl() {
        let mut conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index.query_purl("purl1").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, "116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70");
    }

    #[tokio::test]
    async fn test_query_sha256() {
        let mut conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index.query_sha256("116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, "116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70");
    }
}
