use async_compression::tokio::bufread::{BzDecoder, BzEncoder, ZstdDecoder, ZstdEncoder};
use bytes::Bytes;
use futures::{stream::LocalBoxStream, Stream, StreamExt, TryStreamExt};
use tokio::io::AsyncRead;
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

pub type ObjectStream<'a> = LocalBoxStream<'a, Result<Bytes, Error>>;

pub fn stream_reader<'a>(
    encoding: Option<&str>,
    data: impl Stream<Item = Result<Bytes, Error>> + Unpin + 'a,
) -> Result<Box<dyn AsyncRead + Unpin + 'a>, Error> {
    match encoding {
        None => Ok(Box::new(StreamReader::new(encode_zstd(Box::pin(data))))),
        Some(s) => match s {
            "zstd" | "bzip2" => Ok(Box::new(StreamReader::new(data))),
            e => Err(Error::Encoding(e.to_string())),
        },
    }
}

pub fn decode<'a>(encoding: Option<&str>, stream: ObjectStream<'a>) -> Result<ObjectStream<'a>, Error> {
    match encoding {
        Some(s) => match s {
            "zstd" => Ok(decode_zstd(stream)),
            "bzip2" => Ok(decode_bzip(stream)),
            _ => Err(Error::Encoding(s.to_string())),
        },
        None => Ok(stream),
    }
}

fn decode_zstd(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(ZstdDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}

fn decode_bzip(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(BzDecoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}

pub fn encode<'a>(encoding: Option<&str>, stream: ObjectStream<'a>) -> Result<ObjectStream<'a>, Error> {
    match encoding {
        Some(s) => match s {
            "zstd" => Ok(encode_zstd(stream)),
            "bzip2" => Ok(encode_bzip(stream)),
            _ => Err(Error::Encoding(s.to_string())),
        },
        None => Ok(stream),
    }
}

fn encode_zstd(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(ZstdEncoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}

fn encode_bzip(s: ObjectStream) -> ObjectStream {
    ReaderStream::new(BzEncoder::new(StreamReader::new(s)))
        .map_err(Error::Io)
        .boxed_local()
}
