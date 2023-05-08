use std::fmt::Display;
use std::path::PathBuf;

pub struct Index {
    connection: sqlite::Connection,
    path: Option<PathBuf>,
}

#[derive(Debug)]
pub enum Error {
    Open,
    Internal(sqlite::Error),
    NotFound,
    NotPersisted,
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Error opening index"),
            Self::Internal(e) => write!(f, "Internal error: {:?}", e),
            Self::NotFound => write!(f, "Not found"),
            Self::NotPersisted => write!(f, "Database is not persisted"),
            Self::Io(e) => write!(f, "I/O error: {:?}", e),
        }
    }
}

impl std::error::Error for Error {}

// TODO: SCHEMA migration not supported right now...
const SCHEMA: &str = include_str!("../schema.sql");

impl Index {
    pub fn new(path: &PathBuf) -> Result<Self, Error> {
        let connection = sqlite::open(path).map_err(|_| Error::Open)?;
        // TODO: Handle error
        let _ = connection.execute(SCHEMA);
        Ok(Self {
            connection,
            path: Some(path.clone()),
        })
    }

    // Update index data and reopen
    pub fn sync(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(path) = &self.path {
            std::fs::write(path, data).map_err(Error::Io)?;
            self.connection = sqlite::open(path).map_err(|_| Error::Open)?;
        }
        Ok(())
    }

    pub fn new_with_handle(connection: sqlite::Connection) -> Self {
        Self { connection, path: None }
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

    pub async fn insert(&mut self, purl: &str, sha256: &str, obj: &str) -> Result<(), Error> {
        const INSERT_PURL: &str = "INSERT INTO sboms VALUES (?, ?, ?)";
        let mut statement = self.connection.prepare(INSERT_PURL)?;
        statement.bind(&[(1, purl), (2, sha256), (3, obj)][..])?;
        loop {
            let state = statement.next()?;
            if state == sqlite::State::Done {
                break;
            }
        }
        Ok(())
    }

    pub fn snapshot(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(path) = &self.path {
            let data = std::fs::read(path).map_err(Error::Io)?;
            Ok(data)
        } else {
            Err(Error::NotPersisted)
        }
    }
}

impl From<sqlite::Error> for Error {
    fn from(e: sqlite::Error) -> Self {
        Self::Internal(e)
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
    async fn test_insert() {
        let mut conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index
            .insert(
                "purl2",
                "116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c71",
                "key1",
            )
            .await;
        assert!(result.is_ok());

        let result = index.query_purl("purl2").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, "key1");
    }

    #[tokio::test]
    async fn test_query_purl() {
        let mut conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index.query_purl("purl1").await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(
            result,
            "116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70"
        );
    }

    #[tokio::test]
    async fn test_query_sha256() {
        let mut conn = sqlite::open(":memory:").unwrap();
        init(&mut conn);

        let mut index = Index::new_with_handle(conn);

        let result = index
            .query_sha256("116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70")
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(
            result,
            "116940abae80491f5357f652e55c48347dd7a2a1ff27df578c4572a383373c70"
        );
    }
}
