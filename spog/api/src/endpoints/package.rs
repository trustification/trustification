use crate::search;
use crate::service::guac::GuacService;
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use spog_model::package_info::{PackageInfo, V11yRef};
use spog_model::prelude::{PackageProductDetails, ProductRelatedToPackage};
use std::sync::Arc;
use trustification_api::search::SearchResult;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;
use utoipa::IntoParams;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/package")
                .wrap(new_auth!(auth))
                .service(web::resource("/search").to(package_search_mock))
                .service(web::resource("/related").to(get_related))
                .service(web::resource("/dependencies").to(get_dependencies))
                .service(web::resource("/dependents").to(get_dependents))
                // these must come last, otherwise the path parameter will eat the rest
                .service(web::resource("/{id}").to(package_get_mock))
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
pub async fn package_search_mock(query: web::Query<search::QueryParams>) -> actix_web::Result<HttpResponse> {
    let web::Query(_) = query;

    let pkgs = make_mock_data();
    let result = SearchResult {
        total: Some(pkgs.len()),
        result: pkgs,
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
pub async fn package_get_mock(path: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let _id = path.into_inner();

    let pkgs = make_mock_data();
    Ok(HttpResponse::Ok().json(&pkgs[0]))
}

#[utoipa::path(
    get,
    path = "/api/v1/package/{id}/related-products",
    responses(
        (status = 200, description = "related products search was successful", body = PackageProductDetails),
    ),
    params(
        ("id" = Url, Path, description = "The ID of the package to get related products for")
    )
)]
// TODO Replace mock data
pub async fn package_related_products(path: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let _id = path.into_inner();

    let related_products = vec![
        ProductRelatedToPackage {
            sbom_id: "3amp-2.json.bz2".to_string(),
            dependency_type: "Direct".to_string(),
        },
        ProductRelatedToPackage {
            sbom_id: "3amp-2.json.bz2".to_string(),
            dependency_type: "Transitive".to_string(),
        },
    ];
    let result = PackageProductDetails { related_products };
    Ok(HttpResponse::Ok().json(&result))
}

fn make_mock_data() -> Vec<PackageInfo> {
    let packages = vec![
        PackageInfo {
            name: "io.quarkus.arc:arc".to_string().into(),
            version: "2.16.2.Final".to_string().into(),
            package_type: "maven".to_string().into(),
            description: "case one".to_string().into(),
            purl: "pkg:maven/io.quarkus.arc/arc@2.16.2.Final?type=jar".to_string().into(),
            href: Some(format!(
                "/api/package?purl={}",
                &urlencoding::encode("pkg:maven/io.quarkus.arc/arc@2.16.2.Final?type=jar")
            )),
            sbom: Some(format!(
                "/api/package/sbom?purl={}",
                &urlencoding::encode("pkg:maven/io.quarkus.arc/arc@2.16.2.Final?type=jar")
            )),
            supplier: "Organization: Red Hat".to_string().into(),
            vulnerabilities: vec![
                V11yRef {
                    cve: "CVE-2023-5511".to_string(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "low".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "medium".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "high".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "critical".to_string(),
                },
            ],
        },
        PackageInfo {
            name: "redhat:openssl".to_string().into(),
            version: "1.1.1k-7.el8_6".to_string().into(),
            package_type: "rpm".to_string().into(),
            description: "case two".to_string().into(),
            purl: Some("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6".to_string()),
            href: Some(format!(
                "/api/package?purl={}",
                &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6")
            )),
            sbom: Some(format!(
                "/api/package/sbom?purl={}",
                &urlencoding::encode("pkg:rpm/redhat/openssl@1.1.1k-7.el8_6")
            )),
            supplier: "Organization: Red Hat".to_string().into(),
            vulnerabilities: vec![
                V11yRef {
                    cve: "cve-2023-0286".into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "low".to_string(),
                },
                V11yRef {
                    cve: "cve-2023-0286".into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "medium".to_string(),
                },
                V11yRef {
                    cve: "cve-2023-0286".into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "critical".to_string(),
                },
            ],
        },
    ];
    packages
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, IntoParams)]
pub struct GetPackage {
    pub purl: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/packages/related",
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
