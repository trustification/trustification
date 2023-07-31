use actix_web::body::BoxBody;
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse, ResponseError,
};
use bombastic_model::prelude::SBOM;
use bytes::Bytes;
use futures::Stream;
use trustification_auth::authenticator::error::ErrorInformation;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Data(#[from] bombastic_model::data::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Error::Url(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "UrlParseError".into(),
                message: format!("Failed to build request URL: {err}"),
            }),
            Error::Request(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "ClientRequestError".into(),
                message: format!("Failed to perform request: {err}"),
            }),
            Error::Data(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidSBOMFormat".into(),
                message: format!("Unable to parse SBOM: {err}"),
            }),
        }
    }
}

#[derive(Clone)]
pub struct CrdaClient {
    client: reqwest::Client,
    url: Url,
}

impl CrdaClient {
    pub fn new(url: Url) -> Self {
        let client = reqwest::Client::new();
        Self { client, url }
    }

    pub async fn analyze(
        &self,
        sbom: impl Into<reqwest::Body>,
    ) -> Result<impl Stream<Item = reqwest::Result<Bytes>>, Error> {
        Ok(self
            .client
            .post(self.url.join("/analysis")?)
            .body(sbom)
            .send()
            .await?
            .error_for_status()?
            .bytes_stream())
    }
}

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/crda/report").to(report));
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/crda/report",
    responses(
        (status = 200, description = "API", body = String),
    )
)]
async fn report(data: Bytes, crda: web::Data<CrdaClient>) -> actix_web::Result<HttpResponse> {
    Ok(run_report(data, &crda).await?)
}

async fn run_report(data: Bytes, crda: &CrdaClient) -> Result<HttpResponse, Error> {
    SBOM::parse(&data)?;

    let report = crda.analyze(data).await?;
    Ok(HttpResponse::Ok().content_type("text/html").streaming(report))
}
