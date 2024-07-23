use crate::app_state::AppState;
use crate::search;
use crate::service::v11y::V11yService;
use actix_web::web::ServiceConfig;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use spog_model::dashboard::{CSAFStatus, CveStatus, DashboardStatus, SbomStatus};
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::SearchOptions;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/dashboard")
                .wrap(new_auth!(auth))
                .service(web::resource("/status").to(get_status)),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/dashboard/status",
    responses(
    (status = 200, description = "packages search was successful", body = SearchResultPackage),
    ),
    params()
)]
#[instrument(skip(state, access_token, v11y), err)]
pub async fn get_status(
    state: web::Data<AppState>,
    _params: web::Query<search::QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let sbom_status_result = state
        .get_sbom_status(options.clone().into_inner(), &access_token)
        .await?;
    let vex_status_result = state
        .get_vex_status(options.clone().into_inner(), &access_token)
        .await?;
    let cve_status_result = v11y.get_cve_status().await?;

    let status = DashboardStatus {
        sbom_summary: SbomStatus {
            total_sboms: sbom_status_result.total,
            last_updated_sbom_id: sbom_status_result.last_updated_sbom_id,
            last_updated_sbom_name: sbom_status_result.last_updated_sbom_name,
            last_updated_date: sbom_status_result.last_updated_date,
        },
        csaf_summary: CSAFStatus {
            total_csafs: vex_status_result.total,
            last_updated_csaf_id: vex_status_result.last_updated_vex_id,
            last_updated_csaf_name: vex_status_result.last_updated_vex_name,
            last_updated_date: vex_status_result.last_updated_date,
        },
        cve_summary: CveStatus {
            total_cves: cve_status_result.total,
            last_updated_cve: cve_status_result.last_updated_cve_id,
            last_updated_date: cve_status_result.last_updated_date,
        },
    };

    Ok(HttpResponse::Ok().json(status))
}
