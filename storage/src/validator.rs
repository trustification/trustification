use crate::Error;
use bytes::Bytes;
use futures::Stream;
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
    pub async fn validate(
        &self,
        _encoding: Option<&str>,
        data: impl Stream<Item = Result<Bytes, Error>> + Unpin,
    ) -> Result<impl Stream<Item = Result<Bytes, Error>> + Unpin, Error> {
        use Validator::*;
        match self {
            None => Ok(data),
            SBOM => Ok(data), // TODO
            VEX => Ok(data),  // TODO
            Seedwing(_url) => todo!(),
        }
    }
}
