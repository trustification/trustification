//! Structures to work with users and identities.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDetails {
    pub id: String,
    pub roles: Vec<String>,
}

/// Information about the authenticated user, may be anonymous
#[derive(Clone, Debug)]
pub enum UserInformation {
    Authenticated(UserDetails),
    Anonymous,
}

#[allow(unused)]
pub const ANONYMOUS: UserInformation = UserInformation::Anonymous;

static EMPTY_ROLES: Vec<String> = vec![];

#[allow(unused)]
impl UserInformation {
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Authenticated(details) => Some(&details.id),
            Self::Anonymous => None,
        }
    }

    pub fn roles(&self) -> &Vec<String> {
        match self {
            Self::Authenticated(details) => &details.roles,
            Self::Anonymous => &EMPTY_ROLES,
        }
    }
}

/// Extractor for user information.
#[cfg(feature = "actix")]
impl actix_web::FromRequest for UserInformation {
    type Error = actix_web::Error;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;
        match req.extensions().get::<UserInformation>() {
            Some(user) => core::future::ready(Ok(user.clone())),
            None => core::future::ready(Ok(UserInformation::Anonymous)),
        }
    }
}
