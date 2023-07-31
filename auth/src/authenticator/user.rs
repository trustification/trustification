//! Structures to work with users and identities.

use crate::authenticator::error::{AuthenticationError, AuthorizationError};

/// Details of an authenticated user.
///
/// ## Extraction
///
/// This value can be extracted by `actix` like this:
///
/// ```rust
/// # use actix_web::post;
/// # use actix_web::Responder;
/// use trustification_auth::authenticator::user::UserDetails;
///
/// #[post("/api")]
/// async fn perform_operation(
///     user: UserDetails,
/// ) -> impl Responder {
///   // [...]
///   "Hello World"
/// }
/// ```
///
/// Extraction, and the request, will fail with `401` when the user is not authenticated,
/// and `403` when the user is [`UserInformation::Anonymous`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserDetails {
    pub id: String,
    pub roles: Vec<String>,
}

impl UserDetails {
    pub fn require_role(&self, role: impl AsRef<str>) -> Result<(), AuthorizationError> {
        let role = role.as_ref();
        if self.roles.iter().any(|r| r == role) {
            Ok(())
        } else {
            Err(AuthorizationError::Failed)
        }
    }
}

/// Information about the authenticated user, may be anonymous
#[derive(Clone, Debug)]
pub enum UserInformation {
    Authenticated(UserDetails),
    Anonymous,
}

impl UserInformation {
    pub fn require_role(&self, role: impl AsRef<str>) -> Result<(), AuthorizationError> {
        match self {
            Self::Anonymous => Err(AuthorizationError::Failed),
            Self::Authenticated(details) => details.require_role(role),
        }
    }
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

/// Extractor for user details, requires an authenticated user.
#[cfg(feature = "actix")]
impl actix_web::FromRequest for UserDetails {
    type Error = actix_web::Error;
    type Future = core::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        use actix_web::HttpMessage;
        match req.extensions().get::<UserInformation>() {
            Some(UserInformation::Authenticated(details)) => core::future::ready(Ok(details.clone())),
            Some(UserInformation::Anonymous) => core::future::ready(Err(AuthorizationError::Failed.into())),
            None => core::future::ready(Err(AuthenticationError::Failed.into())),
        }
    }
}
