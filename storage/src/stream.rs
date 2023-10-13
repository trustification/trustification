use async_compression::tokio::bufread::{BzDecoder, BzEncoder, ZstdDecoder, ZstdEncoder};
use bytes::Bytes;
use futures::{stream::LocalBoxStream, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

pub type ObjectStream<'a> = LocalBoxStream<'a, Result<Bytes, Error>>;

pub fn encoded_reader<'a>(
    default: &str,
    encoding: Option<&str>,
    data: impl Stream<Item = Result<Bytes, Error>> + Unpin + 'a,
) -> Result<Box<dyn AsyncRead + Unpin + 'a>, Error> {
    Ok(match encoding {
        None => encode(Some(default), Box::pin(data)),
        Some(s) => match s {
            "zstd" | "bzip2" => encode(None, Box::pin(data)),
            e => Err(Error::Encoding(e.to_string())),
        },
    }
    .map(|s| Box::new(StreamReader::new(s)))?)
}

pub fn decode<'a>(encoding: Option<&str>, stream: ObjectStream<'a>) -> Result<ObjectStream<'a>, Error> {
    match encoding {
        Some(s) => match s {
            "zstd" => Ok(boxed(ZstdDecoder::new(StreamReader::new(stream)))),
            "bzip2" => Ok(boxed(BzDecoder::new(StreamReader::new(stream)))),
            _ => Err(Error::Encoding(s.to_string())),
        },
        None => Ok(stream),
    }
}

pub fn encode<'a>(encoding: Option<&str>, stream: ObjectStream<'a>) -> Result<ObjectStream<'a>, Error> {
    match encoding {
        Some(s) => match s {
            "zstd" => Ok(boxed(ZstdEncoder::new(StreamReader::new(stream)))),
            "bzip2" => Ok(boxed(BzEncoder::new(StreamReader::new(stream)))),
            _ => Err(Error::Encoding(s.to_string())),
        },
        None => Ok(stream),
    }
}

fn boxed<'a, T: AsyncRead + 'a>(t: T) -> ObjectStream<'a> {
    ReaderStream::new(t).map_err(Error::Io).boxed_local()
}
