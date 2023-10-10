use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder, ZstdEncoder};
use bytes::Bytes;
use futures::{stream::BoxStream, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

pub type ObjectStream = BoxStream<'static, Result<Bytes, Error>>;

pub fn encode<'a>(
    encoding: Option<&str>,
    data: impl Stream<Item = Result<Bytes, Error>> + Unpin + 'a,
) -> Result<Box<dyn AsyncRead + Unpin + 'a>, Error> {
    match encoding {
        None => Ok(Box::new(ZstdEncoder::new(StreamReader::new(data)))),
        Some(s) => match s {
            "zstd" | "bzip2" => Ok(Box::new(StreamReader::new(data))),
            e => Err(Error::Encoding(e.to_string())),
        },
    }
}

// Returns an unencoded JSON stream
pub fn decode(encoding: Option<String>, stream: ObjectStream) -> Result<ObjectStream, Error> {
    match encoding {
        Some(s) => match s.as_str() {
            "zstd" => Ok(zstd(stream)),
            "bzip2" => Ok(bzip(stream)),
            _ => Err(Error::Encoding(s)),
        },
        None => Ok(stream),
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
