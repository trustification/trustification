use async_compression::tokio::bufread::{BzDecoder, ZstdDecoder};
use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt, TryStreamExt};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::Error;

type ObjectStream = BoxStream<'static, Result<Bytes, Error>>;

// Returns a tuple of encoding type (if any), and a stream
pub fn decode(encoding: Option<String>, stream: ObjectStream) -> (Option<String>, ObjectStream) {
    match encoding {
        Some(ref s) => match s.as_str() {
            "zstd" => (None, zstd(stream)),
            "bzip2" => (None, bzip(stream)),
            _ => (encoding, stream),
        },
        None => (encoding, stream),
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
