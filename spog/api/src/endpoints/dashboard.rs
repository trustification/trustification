use crate::app_state::AppState;
use crate::search;
use crate::service::v11y::V11yService;
use actix_web::web::{PayloadConfig, ServiceConfig};
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use spog_model::dashboard::{CSAFStatus, CveStatus, DashboardStatus, Preferences, SbomStatus, UserPreferences};
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::SearchOptions;
use trustification_auth::authenticator::user::UserInformation;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>, payload_limit: usize) -> impl FnOnce(&mut ServiceConfig) {
    move |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/dashboard")
                .wrap(new_auth!(auth))
                .service(web::resource("/status").to(get_status))
                .service(
                    web::resource("/userPreferences")
                        .app_data(PayloadConfig::new(payload_limit))
                        .route(web::post().to(user_preferences_update))
                        .route(web::get().to(user_preferences_receive)),
                ),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/dashboard/userPreferences",
    responses(
    (status = 200, description = "userPreferences search was successful", body = UserPreferences),
    ),
    params()
)]
#[instrument(skip(state), err)]
pub async fn user_preferences_receive(
    state: web::Data<AppState>,
    user_information: UserInformation,
) -> actix_web::Result<HttpResponse> {
    if let Some(user_id) = user_information.id() {
        let result = state
            .db_storage
            .select_preferences_by_user_id(user_id.to_string())
            .await?;
        Ok(HttpResponse::Ok().json(result.preferences))
    } else {
        Err(actix_web::error::ErrorUnauthorized(401))
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/dashboard/userPreferences",
    responses(
    (status = 200, description = "userPreferences update was successful", body = UserPreferences),
    ),
)]
#[instrument(skip(state), err)]
pub async fn user_preferences_update(
    state: web::Data<AppState>,
    payload: web::Json<Preferences>,
    user_information: UserInformation,
) -> actix_web::Result<HttpResponse> {
    if let Some(user_id) = user_information.id() {
        let up = UserPreferences {
            user_id: user_id.to_string(),
            preferences: Some(payload.into_inner()),
        };
        let result = up.preferences.clone();
        state.db_storage.update_user_preferences(up).await?;
        Ok(HttpResponse::Ok().json(result))
    } else {
        Err(actix_web::error::ErrorUnauthorized(401))
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
