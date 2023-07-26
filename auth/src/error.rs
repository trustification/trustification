#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    #[error("Authentication failed")]
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorInformation {
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for AuthenticatorError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        match self {
            Self::Failed => actix_web::HttpResponse::Forbidden().json(ErrorInformation {
                error: "Forbidden".to_string(),
                message: self.to_string(),
            }),
        }
    }
}
