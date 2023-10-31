use crate::search;
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

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/package_info")
                .wrap(new_auth!(auth))
                .service(web::resource("/search").to(packages_search_mock))
                .service(web::resource("/{id}").to(package_get_mock))
                .service(web::resource("/{id}/related-products").to(package_related_products)),
        );
    }
}

#[utoipa::path(
get,
path = "/api/v1/package_info/search",
responses(
(status = 200, description = "packages was found"),
(status = NOT_FOUND, description = "packages was not found")
),
params(
("id" = String, Path, description = "Id of advisory to fetch"),
)
)]

pub async fn packages_search_mock(
    web::Query(params): web::Query<search::QueryParams>,
) -> actix_web::Result<HttpResponse> {
    let pkgs = make_mock_data();
    let result = SearchResult::<Vec<PackageInfo>> {
        total: Some(pkgs.len()),
        result: pkgs,
    };
    Ok(HttpResponse::Ok().json(result))
}

pub async fn package_get_mock(web::Query(params): web::Query<search::QueryParams>) -> actix_web::Result<HttpResponse> {
    let pkgs = make_mock_data();
    Ok(HttpResponse::Ok().json(&pkgs[0]))
}

// TODO Replace mock data
pub async fn package_related_products(
    web::Query(params): web::Query<search::QueryParams>,
) -> actix_web::Result<HttpResponse> {
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
    let mut packages = vec![
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
                    cve: "CVE-2023-5511".to_string().into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "low".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string().into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "medium".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string().into(),
                    href: "https://access.redhat.com/security/cve/cve-2023-0286".into(),
                    severity: "high".to_string(),
                },
                V11yRef {
                    cve: "CVE-2023-5511".to_string().into(),
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
