use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder, ZstdEncoder};
use bytes::{Buf, Bytes};
use futures::{stream::BoxStream, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

type ObjectStream = BoxStream<'static, Result<Bytes, Error>>;

pub fn encode<'a, S, B, E>(encoding: Option<&'a str>, data: &'a mut S) -> Result<Box<dyn AsyncRead + Unpin + 'a>, Error>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: Buf + 'a,
    E: Into<std::io::Error>,
{
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
