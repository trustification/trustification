#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("Authentication failed")]
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("Authorization failed")]
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorInformation {
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthenticationError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::Failed => actix_web::HttpResponse::Unauthorized().json(ErrorInformation {
                error: "Unauthorized".to_string(),
                message: self.to_string(),
            }),
        }
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthorizationError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::Failed => actix_web::HttpResponse::Forbidden().json(ErrorInformation {
                error: "Forbidden".to_string(),
                message: self.to_string(),
            }),
        }
    }
}
