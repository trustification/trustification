use actix_web::{
    body::BoxBody,
    web::{self, PayloadConfig, ServiceConfig},
    HttpResponse, ResponseError,
};
use bombastic_model::prelude::SBOM;
use bytes::Bytes;
use futures::Stream;
use http::header;
use tracing::instrument;
use trustification_common::error::ErrorInformation;
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
                message: format!("Failed to build request URL"),
                details: err.to_string(),
            }),
            Error::Request(err) => HttpResponse::BadGateway().json(ErrorInformation {
                error: "ClientRequestError".into(),
                message: format!("Failed to contact the analytics server"),
                details: err.to_string(),
            }),
            Error::Data(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidSBOMFormat".into(),
                message: format!("Unable to parse SBOM"),
                details: err.to_string(),
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

    #[instrument(skip(self, sbom), fields(sbom_size = sbom.as_bytes().map(|b|b.len())), err)]
    pub async fn analyze(
        &self,
        sbom: reqwest::Body,
        content_type: &str,
    ) -> Result<impl Stream<Item = reqwest::Result<Bytes>>, Error> {
        Ok(self
            .client
            .post(self.url.join("api/v3/analysis")?)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, "text/html")
            .body(sbom)
            .send()
            .await?
            .error_for_status()
            .map(|r| {
                log::info!("CRDA response: {}", r.status());
                r
            })?
            .bytes_stream())
    }
}

pub(crate) fn configure(payload_limit: usize) -> impl FnOnce(&mut ServiceConfig) {
    move |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/analyze/report")
                .app_data(PayloadConfig::new(payload_limit))
                .to(report),
        );
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/analyze/report",
    responses(
        (status = 200, description = "Generated CRDA report", body = String),
        (status = 400, description = "Invalid SBOM format", body = String),
        (status = 502, description = "Failed to communicate with CRDA backend", body = String),
    )
)]
async fn report(data: Bytes, crda: web::Data<CrdaClient>) -> actix_web::Result<HttpResponse> {
    Ok(run_report(data, &crda).await?)
}

async fn run_report(data: Bytes, crda: &CrdaClient) -> Result<HttpResponse, Error> {
    let sbom = SBOM::parse(&data)?;

    let r#type = match &sbom {
        SBOM::SPDX(_) => "application/vnd.spdx+json",
        SBOM::CycloneDX(_) => "application/vnd.cyclonedx+json",
    };

    let report = crda.analyze(data.into(), r#type).await?;
    Ok(HttpResponse::Ok().content_type("text/html").streaming(report))
}
