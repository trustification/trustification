use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

pub const MIME_ZSTD: &str = "application/zstd";
pub const MIME_BZIP: &str = "application/x-bzip2";

type ObjectStream = BoxStream<'static, Result<Bytes, Error>>;

pub fn decode(content_type: Option<String>, stream: ObjectStream) -> (Option<String>, ObjectStream) {
    match content_type {
        Some(ref s) => match s.as_str() {
            MIME_ZSTD => (Some(mime::APPLICATION_JSON.to_string()), zstd(stream)),
            MIME_BZIP => (Some(mime::APPLICATION_JSON.to_string()), bzip(stream)),
            _ => (content_type, stream),
        },
        None => (content_type, stream),
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
