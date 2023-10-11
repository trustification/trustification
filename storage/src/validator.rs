use super::stream::ObjectStream;
use crate::Error;
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
        _encoding: Option<&str>,
        data: ObjectStream<'a>,
    ) -> Result<ObjectStream<'a>, Error> {
        use Validator::*;
        match self {
            None => Ok(data),
            SBOM => {
                let mut bytes = vec![];
                pin_mut!(data);
                while let Some(chunk) = data.next().await {
                    bytes.extend_from_slice(&chunk?)
                }
                let _ = SBOMValidator::parse(&bytes).map_err(|e| {
                    log::error!("Invalid SBOM: {e}");
                    Error::InvalidContent
                })?;
                Ok(Box::pin(once(ok(Bytes::copy_from_slice(&bytes)))))
            }
            VEX => Ok(data), // TODO
            Seedwing(_url) => todo!(),
        }
    }
}
