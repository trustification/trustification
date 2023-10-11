use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder, ZstdEncoder};
use bytes::Bytes;
use futures::{stream::LocalBoxStream, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

pub type ObjectStream<'a> = LocalBoxStream<'a, Result<Bytes, Error>>;

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
pub fn decode<'a>(encoding: Option<&str>, stream: ObjectStream<'a>) -> Result<ObjectStream<'a>, Error> {
    match encoding {
        Some(s) => match s {
            "zstd" => Ok(zstd(stream)),
            "bzip2" => Ok(bzip(stream)),
            _ => Err(Error::Encoding(s.to_string())),
        },
        None => Ok(stream),
    }
}

fn zstd(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(ZstdDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}

fn bzip(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(BzDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}
