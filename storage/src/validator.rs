use crate::{
    stream::{decode, encode, ObjectStream},
    Error,
};
use bombastic_model::prelude::SBOM as SBOMValidator;
use bytes::Bytes;
use futures::{future::ok, pin_mut, stream::once, StreamExt};
use std::fmt;
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

impl fmt::Display for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Validator::None => write!(f, ""),
            Validator::SBOM => write!(f, "sbom"),
            Validator::VEX => write!(f, "vex"),
            Validator::Seedwing(_) => write!(f, "seedwing"),
        }
    }
}

impl Validator {
    pub async fn validate<'a>(
        &self,
        encoding: Option<&str>,
        data: ObjectStream<'a>,
    ) -> Result<ObjectStream<'a>, Error> {
        use Validator::*;
        match self {
            None => Ok(data),
            SBOM => {
                check(encoding, data, |bytes| {
                    SBOMValidator::parse(bytes).map_err(|e| {
                        log::error!("Invalid SBOM: {e}");
                        Error::InvalidContent
                    })
                })
                .await
            }
            VEX => {
                check(encoding, data, |bytes| {
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
    encoding: Option<&str>,
    data: ObjectStream<'a>,
    parse: F,
) -> Result<ObjectStream<'a>, Error> {
    let data = decode(encoding, data)?;
    let mut bytes = vec![];
    pin_mut!(data);
    while let Some(chunk) = data.next().await {
        bytes.extend_from_slice(&chunk?)
    }
    parse(&bytes)?;
    let s = once(ok(Bytes::copy_from_slice(&bytes)));
    Ok(Box::pin(encode(encoding, Box::pin(s))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(data: ObjectStream<'_>) -> Vec<u8> {
        let mut bytes = vec![];
        pin_mut!(data);
        while let Some(chunk) = data.next().await {
            bytes.extend_from_slice(&chunk.unwrap())
        }
        bytes
    }

    async fn test(v: Validator, enc: Option<&str>, expected: &[u8]) -> Result<Vec<u8>, Error> {
        let src = once(ok(Bytes::copy_from_slice(expected)));
        let sink = v.validate(enc, Box::pin(src)).await?;
        Ok(read(Box::pin(sink)).await)
    }

    #[tokio::test]
    async fn none() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json");
        let result = test(Validator::None, None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[tokio::test]
    async fn sbom_json_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json");
        let result = test(Validator::SBOM, None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[tokio::test]
    async fn sbom_json_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json");
        assert!(test(Validator::SBOM, None, expected).await.is_err())
    }

    #[tokio::test]
    async fn sbom_bzip2_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json.bz2");
        let result = test(Validator::SBOM, Some("bzip2"), expected).await?;
        // This exact file was obtained from a Red Hat internal
        // repo. I think it's safe to ignore the 4-byte bz2 header, as
        // it's the block-size (4th byte) that's different: 6 vs 9. I
        // think we can chalk that up to different bzip2 encoders.
        Ok(assert_eq!(expected[4..], result[4..]))
    }

    #[tokio::test]
    async fn sbom_bzip2_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json.bz2");
        assert!(test(Validator::SBOM, Some("bzip2"), expected).await.is_err())
    }

    #[tokio::test]
    async fn sbom_bzip2_invalid_license() {
        let expected = include_bytes!("../../bombastic/testdata/3amp-2.json.bz2");
        assert!(test(Validator::SBOM, Some("bzip2"), expected).await.is_err())
    }

    #[tokio::test]
    async fn sbom_zstd_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-valid.json.zst");
        let result = test(Validator::SBOM, Some("zstd"), expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[tokio::test]
    async fn sbom_zstd_invalid() {
        let expected = include_bytes!("../../bombastic/testdata/ubi8-invalid.json.zst");
        assert!(test(Validator::SBOM, Some("zstd"), expected).await.is_err())
    }

    #[tokio::test]
    async fn vex_json_valid() -> Result<(), Error> {
        let expected = include_bytes!("../../vexination/testdata/rhsa-2023_1441.json");
        let result = test(Validator::VEX, None, expected).await?;
        Ok(assert_eq!(expected[..], result[..]))
    }

    #[tokio::test]
    async fn vex_json_invalid() {
        let expected = include_bytes!("../../vexination/testdata/rhsa-2023_1441.json");
        assert!(test(Validator::VEX, None, &expected[10..]).await.is_err())
    }
}
