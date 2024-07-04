use crate::{
    stream::{decode, encode, ObjectStream},
    Error,
};
use bombastic_model::prelude::SBOM as SBOMValidator;
use bytes::Bytes;
use bytesize::ByteSize;
use futures::{future::ok, pin_mut, stream::once, StreamExt};
use std::str::FromStr;

#[derive(Clone, Debug, Default)]
pub enum Validator {
    #[default]
    None,
    SBOM,
    VEX,
    Seedwing(String), // TODO
}

impl FromStr for Validator {
    type Err = std::str::Utf8Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Validator::*;
        match s {
            "none" => Ok(None),
            "sbom" => Ok(SBOM),
            "vex" => Ok(VEX),
            url => Ok(Seedwing(url.to_string())),
        }
    }
}

impl Validator {
    pub async fn validate<'a>(
        &self,
        size: ByteSize,
        encoding: Option<&str>,
        data: ObjectStream<'a>,
    ) -> Result<ObjectStream<'a>, Error> {
        use Validator::*;
        match self {
            None => check(size, encoding, data, |_| Ok(())).await,
            SBOM => {
                check(size, encoding, data, |bytes| {
                    SBOMValidator::parse(bytes).map_err(|e| {
                        log::error!("Invalid SBOM: {e}");
                        Error::InvalidContent
                    })
                })
                .await
            }
            VEX => {
                check(size, encoding, data, |bytes| {
                    serde_json::from_slice::<csaf::Csaf>(bytes).map_err(|e| {
                        log::error!("Invalid VEX: {e}");
                        Error::InvalidContent
                    })
                })
                .await
            }
            Seedwing(_url) => todo!(),
        }
    }
}

async fn check<'a, T, F: Fn(&[u8]) -> Result<T, Error>>(
    max: ByteSize,
    encoding: Option<&str>,
    data: ObjectStream<'a>,
    parse: F,
) -> Result<ObjectStream<'a>, Error> {
    let data = decode(encoding, data)?;
    let mut bytes = vec![];
    pin_mut!(data);
    while let Some(chunk) = data.next().await {
        let slice = &chunk?;
        if bytes.len() + slice.len() > max.0 as usize {
            return Err(Error::ExceedsMaxSize(max));
        }
        bytes.extend_from_slice(slice)
    }
    parse(&bytes)?;
    let s = once(ok(Bytes::copy_from_slice(&bytes)));
    Ok(Box::pin(encode(encoding, Box::pin(s))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    async fn read(data: ObjectStream<'_>) -> Vec<u8> {
        let mut bytes = vec![];
        pin_mut!(data);
        while let Some(chunk) = data.next().await {
            bytes.extend_from_slice(&chunk.unwrap())
        }
        bytes
    }

    async fn test(v: Validator, max: ByteSize, enc: Option<&str>, expected: &[u8]) -> Result<Vec<u8>, Error> {
        let src = once(ok(Bytes::copy_from_slice(expected)));
        let sink = v.validate(max, enc, Box::pin(src)).await?;
        Ok(read(Box::pin(sink)).await)
    }

    #[test(tokio::test)]
    async fn none() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json");
        let result = test(Validator::None, ByteSize::kb(100), None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[test(tokio::test)]
    async fn none_too_big() {
        // Even non-validated docs are subject to max size
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json");
        match test(Validator::None, ByteSize::b(100), None, expected).await.err() {
            Some(Error::ExceedsMaxSize(_)) => (),
            Some(e) => panic!("got {e} instead of ExceedsMaxSize"),
            None => panic!("should've gotten ExceedsMaxSize"),
        }
    }

    #[test(tokio::test)]
    async fn sbom_json_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json");
        let result = test(Validator::SBOM, ByteSize::kb(100), None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[test(tokio::test)]
    async fn sbom_json_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json");
        assert!(test(Validator::SBOM, ByteSize::kb(100), None, expected).await.is_err())
    }

    #[test(tokio::test)]
    async fn sbom_bzip2_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json.bz2");
        let result = test(Validator::SBOM, ByteSize::kb(100), Some("bzip2"), expected).await?;
        // This exact file was obtained from a Red Hat internal
        // repo. I think it's safe to ignore the 4-byte bz2 header, as
        // it's the block-size (4th byte) that's different: 6 vs 9. I
        // think we can chalk that up to different bzip2 encoders.
        Ok(assert_eq!(expected[4..], result[4..]))
    }

    #[test(tokio::test)]
    async fn sbom_bzip2_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json.bz2");
        assert!(test(Validator::SBOM, ByteSize::kb(100), Some("bzip2"), expected)
            .await
            .is_err())
    }

    #[test(tokio::test)]
    async fn sbom_bzip2_bigjunk() {
        let expected = include_bytes!("../../bombastic/testdata/bigjunk.bz2");
        match test(Validator::SBOM, ByteSize::kb(100), Some("bzip2"), expected)
            .await
            .err()
        {
            Some(Error::ExceedsMaxSize(_)) => (),
            Some(e) => panic!("got {e} instead of ExceedsMaxSize"),
            None => panic!("should've gotten ExceedsMaxSize"),
        }
    }

    #[test(tokio::test)]
    async fn sbom_bzip2_invalid_license() {
        let expected = include_bytes!("../../bombastic/testdata/3amp-2.json.bz2");
        match test(Validator::SBOM, ByteSize::gb(1), Some("bzip2"), expected)
            .await
            .err()
        {
            Some(Error::InvalidContent) => (),
            Some(e) => panic!("got `{e}` instead of InvalidContent"),
            None => panic!("should've gotten InvalidContent"),
        }
    }

    #[test(tokio::test)]
    async fn sbom_zstd_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json.zst");
        let result = test(Validator::SBOM, ByteSize::kb(100), Some("zstd"), expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[test(tokio::test)]
    async fn sbom_zstd_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json.zst");
        assert!(test(Validator::SBOM, ByteSize::kb(100), Some("zstd"), expected)
            .await
            .is_err())
    }

    #[test(tokio::test)]
    async fn vex_json_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../vexination/testdata/rhsa-2023_1441.json");
        let result = test(Validator::VEX, ByteSize::kb(100), None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[test(tokio::test)]
    async fn vex_json_invalid() {
        let expected = include_bytes!("../../vexination/testdata/rhsa-2023_1441.json");
        assert!(test(Validator::VEX, ByteSize::kb(100), None, &expected[10..])
            .await
            .is_err())
    }

    #[test(tokio::test)]
    async fn sbom_json_cyclonedx_missing_serial_number() {
        let expected = include_bytes!("../../bombastic/testdata/sbom-without-serialNumber.cyclonedx.json");
        let result = test(Validator::SBOM, ByteSize::kb(100), None, expected).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), Error::InvalidContent.to_string());
    }
}
