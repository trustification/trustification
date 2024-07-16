use crate::app_state::AppState;
use crate::search;
use crate::service::v11y::V11yService;
use actix_web::web::ServiceConfig;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::instrument;
use trustification_api::search::SearchOptions;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct DashboardStatus {
    pub sbom_summary: SbomSummary,
    pub csaf_summary: CSAFSummary,
    pub cve_summary: CveSummary,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct SbomSummary {
    pub total_sboms: u64,
    pub last_updated_sbom: String,
    pub last_updated_date: OffsetDateTime,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CSAFSummary {
    pub total_csafs: u64,
    pub last_updated_csaf: String,
    pub last_updated_date: OffsetDateTime,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct CveSummary {
    pub last_updated_cve: String,
    pub last_updated_date: OffsetDateTime,
}

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
    params: web::Query<search::QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let status = make_mock_data();
    Ok(HttpResponse::Ok().json(serde_json::to_string(&status).unwrap()))
}

fn make_mock_data() -> DashboardStatus {
    DashboardStatus {
        sbom_summary: SbomSummary {
            total_sboms: 10,
            last_updated_sbom: "mocked_sbom".to_string(),
            last_updated_date: OffsetDateTime::now_utc(),
        },
        csaf_summary: CSAFSummary {
            total_csafs: 15,
            last_updated_csaf: "mocked_csaf".to_string(),
            last_updated_date: OffsetDateTime::now_utc(),
        },
        cve_summary: CveSummary {
            last_updated_cve: "mocked_cve".to_string(),
            last_updated_date: OffsetDateTime::now_utc(),
        },
    }
}
