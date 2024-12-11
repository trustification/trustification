use crate::app_state::AppState;
use crate::error::Error;
use crate::license::{license_exporter, license_scanner};
use crate::utils::get_sanitize_filename;
use actix_web::web::{Data, PayloadConfig, ServiceConfig};
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bombastic_model::data::SBOM;
use bytes::BytesMut;
use futures::TryStreamExt;
use tracing::{info_span, instrument, Instrument};
use trustification_auth::client::TokenProvider;

extern crate sanitize_filename;

pub(crate) fn configure(payload_limit: usize) -> impl FnOnce(&mut ServiceConfig) {
    move |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/sbom/license/{id}")
                .app_data(PayloadConfig::new(payload_limit))
                .to(download_licenses),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/sbom/license/{id}",
    responses(
    (status = OK, description = "SBOM license was found"),
    (status = NOT_FOUND, description = "SBOM license was not found")
    ),
)]
#[instrument(skip(state, access_token), err)]
pub async fn download_licenses(
    state: web::Data<AppState>,
    web::Query(GetParams { token }): web::Query<GetParams>,
    id: web::Path<String>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let token = token.or_else(|| access_token.map(|s| s.token().to_string()));
    let sbom_id = id.into_inner();
    let sbom = get_sbom(state, sbom_id.as_str(), &token).await?;
    let scanner = license_scanner::LicenseScanner::new(sbom);
    let sbom_licenses = scanner.scanner()?;

    let sbom_name = sbom_licenses.sbom_name.clone();
    let exporter = license_exporter::LicenseExporter::new(sbom_licenses);
    let zip = exporter.generate()?;

    Ok(HttpResponse::Ok()
        .content_type("application/gzip")
        .append_header((
            "Content-Disposition",
            format!(
                "attachment; filename=\"{}_licenses.tar.gz\"",
                get_sanitize_filename(sbom_name)
            ),
        ))
        .body(zip))
}

async fn get_sbom(state: Data<AppState>, id: &str, provider: &dyn TokenProvider) -> Result<SBOM, Error> {
    let sbom: BytesMut = state
        .get_sbom(id, provider)
        .await?
        .try_collect()
        .instrument(info_span!("download SBOM data"))
        .await?;

    let sbom =
        SBOM::parse(&sbom).map_err(|err| crate::error::Error::Generic(format!("Unable to parse SBOM: {err}")))?;
    Ok(sbom)
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct GetParams {
    /// Access token to use for authentication
    pub token: Option<String>,
}
