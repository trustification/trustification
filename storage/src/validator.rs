use crate::{
    stream::{decode, encode, ObjectStream},
    Error,
};
use bombastic_model::prelude::SBOM as SBOMValidator;
use bytes::Bytes;
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
