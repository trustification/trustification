mod pkg;

pub use pkg::*;
use url::{ParseError, Url};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub url: Url,
}

impl Backend {
    pub fn join(&self, input: impl AsRef<str>) -> Result<Url, Error> {
        Ok(self.url.join(input.as_ref())?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse backend URL: {0}")]
    Url(#[from] ParseError),
    #[error("Failed to request: {0}")]
    Request(#[from] reqwest::Error),
}

pub trait IntoWs {
    fn into_ws(self) -> Url;
}

impl IntoWs for Url {
    fn into_ws(mut self) -> Url {
        if self.scheme() == "http" {
            let _ = self.set_scheme("ws");
        } else {
            let _ = self.set_scheme("wss");
        }
        self
    }
}
