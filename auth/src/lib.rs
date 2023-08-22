pub mod authenticator;
pub mod authorizer;
pub mod client;
pub mod devmode;

#[cfg(feature = "swagger")]
pub mod swagger_ui;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scope {
    ReadDocument,
    CreateDocument,
    DeleteDocument,
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        match self {
            Self::ReadDocument => "read:document",
            Self::CreateDocument => "create:document",
            Self::DeleteDocument => "delete:document",
        }
    }
}
