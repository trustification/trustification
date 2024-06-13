use crate::app_state::{AppState, ResponseError};
use crate::endpoints::sbom::vuln;
use crate::error::Error;
use crate::search;
use crate::service::guac::GuacService;
use crate::service::v11y::V11yService;
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use cve::Cve;
use cvss::v3::Score;
use guac::client::intrinsic::vulnerability::VulnerabilityId;
use spog_model::package_info::{PackageInfo, V11yRef};
use spog_model::prelude::PackageProductDetails;
use std::sync::Arc;
use tracing::instrument;
use tracing::Level;
use trustification_api::search::{SearchOptions, SearchResult};
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;
use utoipa::IntoParams;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/package")
                .wrap(new_auth!(auth))
                .service(web::resource("/search").to(package_search))
                .service(web::resource("/related").to(get_related))
                .service(web::resource("/dependencies").to(get_dependencies))
                .service(web::resource("/dependents").to(get_dependents))
                // these must come last, otherwise the path parameter will eat the rest
                .service(web::resource("/{id}").to(package_get))
                .service(web::resource("/{id}/related-products").to(package_related_products)),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/package/search",
    responses(
        (status = 200, description = "packages search was successful", body = SearchResultPackage),
    ),
    params()
)]
#[instrument(skip(state, access_token, guac, v11y), err)]
pub async fn package_search(
    state: web::Data<AppState>,
    params: web::Query<search::QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
    guac: web::Data<GuacService>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let params = params.into_inner();
    log::trace!("Querying package using {}", params.q);
    let data = state
        .search_package(
            &params.q,
            params.offset,
            params.limit,
            options.into_inner(),
            &access_token,
        )
        .await?;
    let mut m: Vec<PackageInfo> = Vec::with_capacity(data.result.len());
    for item in data.result {
        let item = item.document;
        let purl = item.purl;
        let vulnerabilities = get_vulnerabilities(&guac, &v11y, &purl).await?;
        m.push(PackageInfo { purl, vulnerabilities });
    }

    let result = SearchResult {
        total: Some(data.total),
        result: m,
    };

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    get,
    path = "/api/v1/package/{id}",
    responses(
        (status = OK, description = "packages was found", body = Vec<PackageInfo>),
        (status = NOT_FOUND, description = "packages was not found"),
    ),
    params(
        ("id" = Url, Path, description = "The ID of the package to retrieve")
    )
)]
#[instrument(skip(guac, v11y), err)]
pub async fn package_get(
    guac: web::Data<GuacService>,
    v11y: web::Data<V11yService>,
    path: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let purl = path.into_inner();
    let vulnerabilities = get_vulnerabilities(&guac, &v11y, &purl).await?;
    let pkg = PackageInfo { purl, vulnerabilities };
    Ok(HttpResponse::Ok().json(&pkg))
}

/// Retrieve all vulnerabilities (from VEX and CVE) related to the input purl
#[instrument(skip(guac, v11y), err, ret(level = Level::DEBUG))]
async fn get_vulnerabilities(
    guac: &web::Data<GuacService>,
    v11y: &web::Data<V11yService>,
    purl: &str,
) -> Result<Vec<V11yRef>, Error> {
    let vex_results = guac.certify_vex(purl).await?;
    let mut vulnerabilities: Vec<V11yRef> = vec![];
    for certify_vex in vex_results {
        for vulnerability_id in certify_vex.vulnerability.vulnerability_ids {
            vulnerabilities.push(get_vulnerability(v11y, vulnerability_id).await?);
        }
    }
    let vuln_results = guac.certify_vuln(purl).await?;
    for certify_vuln in vuln_results {
        for vulnerability_id in certify_vuln.vulnerability.vulnerability_ids {
            vulnerabilities.push(get_vulnerability(v11y, vulnerability_id).await?);
        }
    }
    Ok(vulnerabilities)
}

/// Retrieve vulnerability information from V11y
#[instrument(skip(v11y), err, ret(level = Level::DEBUG))]
async fn get_vulnerability(v11y: &web::Data<V11yService>, vulnerability_id: VulnerabilityId) -> Result<V11yRef, Error> {
    let cve = vulnerability_id.vulnerability_id.clone().to_uppercase();
    let severity = Score::from(get_vulnerability_score(v11y, &cve).await?)
        .severity()
        .to_string();
    Ok(V11yRef { cve, severity })
}

/// Retrieve vulnerability score from V11y
#[instrument(skip(v11y), err)]
async fn get_vulnerability_score(v11y: &web::Data<V11yService>, id: &str) -> Result<f64, Error> {
    if let Some(response) = v11y.fetch_cve(id).await?.or_status_error_opt().await? {
        let cve: Cve = response.json().await?;
        if let Some(score) = vuln::get_score(&cve) {
            return Ok(score as f64);
        }
    }
    Ok(0_f64)
}

#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct GetParams {
    /// ID of the SBOM to get vulnerabilities for
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/package/{id}/related-products",
    responses(
        (status = 200, description = "related products search was successful", body = PackageProductDetails),
    ),
    params(
        ("id" = Url, Path, description = "The ID of the package to retrieve"),
        GetParams
    )
)]
pub async fn package_related_products(
    guac: web::Data<GuacService>,
    path: web::Path<String>,
    params: web::Query<GetParams>,
) -> actix_web::Result<HttpResponse> {
    let id = path.into_inner();
    let related_products = guac.product_by_package(&id, params.offset, params.limit).await?;

    let result = PackageProductDetails { related_products };
    Ok(HttpResponse::Ok().json(&result))
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, IntoParams)]
pub struct GetPackage {
    pub purl: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/package/related",
    responses(
        (status = OK, description = "Package was found", body = PackageRefList),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(GetPackage)
)]
pub async fn get_related(
    guac: web::Data<GuacService>,
    web::Query(GetPackage { purl }): web::Query<GetPackage>,
) -> actix_web::Result<HttpResponse> {
    let pkgs = guac.get_packages(&purl).await?;

    Ok(HttpResponse::Ok().json(pkgs))
}

#[utoipa::path(
    get,
    path = "/api/v1/package/dependencies",
    responses(
        (status = OK, description = "Package was found", body = inline(spog_model::pkg::PackageDependencies)),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(GetPackage)
)]
pub async fn get_dependencies(
    guac: web::Data<GuacService>,
    web::Query(GetPackage { purl }): web::Query<GetPackage>,
) -> actix_web::Result<HttpResponse> {
    let deps = guac.get_dependencies(&purl).await?;

    Ok(HttpResponse::Ok().json(deps))
}

#[utoipa::path(
    get,
    path = "/api/v1/package/dependents",
    responses(
        (status = OK, description = "Package was found", body = inline(spog_model::pkg::PackageDependents)),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(GetPackage)
)]
pub async fn get_dependents(
    guac: web::Data<GuacService>,
    web::Query(GetPackage { purl }): web::Query<GetPackage>,
) -> actix_web::Result<HttpResponse> {
    let deps = guac.get_dependents(&purl).await?;

    Ok(HttpResponse::Ok().json(deps))
}
