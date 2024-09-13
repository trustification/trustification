use actix_http::body::BoxBody;
use actix_http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use trustification_common::error::ErrorInformation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    OpenId(#[from] openid::error::Error),
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::OpenId(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());

        match self {
            Error::OpenId(openid) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", openid),
                details: openid.to_string(),
            }),
        }
    }
}
