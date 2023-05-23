use actix_web::http::StatusCode;
use actix_web::web::ServiceConfig;
use actix_web::{error, get, HttpRequest, HttpResponse};
use http::uri::Builder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(index);
    }
}

#[utoipa::path(
    responses(
        (status = 200, description = "API", body = Vec<String>),
    )
)]
#[get("/")]
pub async fn index(req: HttpRequest) -> Result<HttpResponse, ApiError> {
    let mut apis = Vec::new();
    let conn = req.connection_info();

    for api in &["/api/package", "/api/vulnerability", "/swagger-ui/", "/openapi.json"] {
        if let Ok(uri) = Builder::new()
            .authority(conn.host())
            .scheme(conn.scheme())
            .path_and_query(*api)
            .build()
        {
            apis.push(uri.to_string());
        }
    }
    Ok(HttpResponse::Ok().json(apis))
}

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ApiError {
    #[error("No query argument was specified")]
    MissingQueryArgument,
    #[error("CVE {cve} was not found")]
    NotFound { cve: String },
}

impl error::ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "status": self.status_code().as_u16(),
            "error": self.to_string(),
        }))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::MissingQueryArgument => StatusCode::BAD_REQUEST,
            ApiError::NotFound { cve: _ } => StatusCode::NOT_FOUND,
        }
    }
}
