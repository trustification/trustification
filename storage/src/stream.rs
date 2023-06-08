use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder};
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt, TryStreamExt};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

type ObjectStream = BoxStream<'static, Result<Bytes, Error>>;

// Returns an unencoded JSON stream
pub fn decode(encoding: Option<String>, stream: ObjectStream) -> Result<ObjectStream, Error> {
    match encoding {
        Some(s) => match s.as_str() {
            "zstd" => Ok(zstd(stream)),
            "bzip2" => Ok(bzip(stream)),
            _ => Err(Error::Encoding(s)),
        },
        None => Err(Error::Encoding("none".to_string())),
    }
}

fn zstd(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(ZstdDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed()
}

fn bzip(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(BzDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed()
}
