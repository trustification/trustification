use crate::guac::service::GuacService;
use crate::search;
use crate::server::{AppState, Error};
use crate::service::collectorist::CollectoristService;
use crate::service::v11y::V11yService;
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse, HttpResponseBuilder,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::BytesMut;
use csaf::definitions::ProductIdT;
use csaf::Csaf;
use futures::TryStreamExt;
use spog_model::csaf::{find_product_relations, trace_product};
use spog_model::cve::{
    AdvisoryOverview, CveDetails, PackageRelatedToProductCve, ProductCveStatus, ProductRelatedToCve,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::client::{BearerTokenProvider, TokenProvider};
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/cve")
                .wrap(new_auth!(auth))
                .service(web::resource("").to(cve_search))
                .service(web::resource("/{id}").to(cve_get))
                .service(web::resource("/{id}/related-products").to(cve_details_mock)),
        );
    }
}

async fn cve_search(
    web::Query(params): web::Query<search::QueryParams>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(v11y.search(params).await.map_err(Error::V11y)?))
}

async fn cve_get(id: web::Path<String>, v11y: web::Data<V11yService>) -> actix_web::Result<HttpResponse> {
    let id = id.into_inner();

    let response = v11y.fetch(&id).await?;

    Ok(HttpResponseBuilder::new(response.status()).streaming(response.bytes_stream()))
}

// TODO remove this method using real data
async fn cve_details_mock(
    app_state: web::Data<AppState>,
    guac: web::Data<GuacService>,
    id: web::Path<String>,
    access_token: BearerAuth,
    collectorist: web::Data<CollectoristService>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let mut products = BTreeMap::<ProductCveStatus, Vec<ProductRelatedToCve>>::new();
    products.insert(
        ProductCveStatus::Fixed,
        vec![ProductRelatedToCve {
            sbom_id: "3amp-2.json.bz2".to_string(),
            packages: vec![
                PackageRelatedToProductCve {
                    r#type: "Direct".to_string(),
                    purl: "pkg:rpm/redhat/3scale-amp-template".to_string(),
                },
                PackageRelatedToProductCve {
                    r#type: "Transitive".to_string(),
                    purl: "pkg:oci/redhat/3scale-rhel7-operator-metadata".to_string(),
                },
            ],
        }],
    );
    products.insert(
        ProductCveStatus::FirstFixed,
        vec![ProductRelatedToCve {
            sbom_id: "amq-ic-1.json.bz2".to_string(),
            packages: vec![
                PackageRelatedToProductCve {
                    r#type: "Direct".to_string(),
                    purl: "pkg:npm/abab@2.0.4".to_string(),
                },
                PackageRelatedToProductCve {
                    r#type: "Transitive".to_string(),
                    purl: "pkg:npm/adjust-sourcemap-loader@2.0.0".to_string(),
                },
            ],
        }],
    );
    products.insert(
        ProductCveStatus::FirstAffected,
        vec![ProductRelatedToCve {
            sbom_id: "ansible_automation_platform-1.2.json.bz2".to_string(),
            packages: vec![
                PackageRelatedToProductCve {
                    r#type: "Direct".to_string(),
                    purl: "pkg:rpm/redhat/PyYAML".to_string(),
                },
                PackageRelatedToProductCve {
                    r#type: "Transitive".to_string(),
                    purl: "pkg:rpm/redhat/acl".to_string(),
                },
            ],
        }],
    );
    products.insert(
        ProductCveStatus::KnownAffected,
        vec![ProductRelatedToCve {
            sbom_id: "ceph-3.json.bz2".to_string(),
            packages: vec![
                PackageRelatedToProductCve {
                    r#type: "Direct".to_string(),
                    purl: "pkg:npm/JSV@4.0.2".to_string(),
                },
                PackageRelatedToProductCve {
                    r#type: "Transitive".to_string(),
                    purl: "pkg:npm/acorn-es7-plugin@1.1.7".to_string(),
                },
            ],
        }],
    );
    products.insert(
        ProductCveStatus::LastAffected,
        vec![ProductRelatedToCve {
            sbom_id: "mtv-2.3.json.bz2".to_string(),
            packages: vec![
                PackageRelatedToProductCve {
                    r#type: "Direct".to_string(),
                    purl: "pkg:golang/github.com/petar/GoLLRB@v0.0.0-20130427215148-53be0d36a84c".to_string(),
                },
                PackageRelatedToProductCve {
                    r#type: "Transitive".to_string(),
                    purl: "pkg:npm/acorn-import-assertions@1.8.0".to_string(),
                },
            ],
        }],
    );
    products.insert(
        ProductCveStatus::KnownNotAffected,
        vec![ProductRelatedToCve {
            sbom_id: "openjdk-1.8.json.bz2".to_string(),
            packages: vec![PackageRelatedToProductCve {
                r#type: "Direct".to_string(),
                purl: "git://pkgs.devel.redhat.com/rpms/java-1.8.0-openjdk".to_string(),
            }],
        }],
    );
    products.insert(ProductCveStatus::Recommended, vec![ProductRelatedToCve {
        sbom_id: "fuse-7.json.bz2".to_string(),
        packages: vec![
            PackageRelatedToProductCve {
                r#type: "Direct".to_string(),
                purl: "git+http://code.engineering.redhat.com/gerrit/jboss-fuse/modeshape.git#b8d75eee71a53f20b789eba8f003a9469f8bc9cd".to_string(),
            },
        ],
    }]);
    products.insert(
        ProductCveStatus::UnderInvestigation,
        vec![ProductRelatedToCve {
            sbom_id: "fuse-7.json.bz2".to_string(),
            packages: vec![PackageRelatedToProductCve {
                r#type: "Direct".to_string(),
                purl: "git://pkgs.devel.redhat.com/rpms/java-1.8.0-openjdk".to_string(),
            }],
        }],
    );

    let result = CveDetails {
        id: id.to_string(),
        details: vec![],
        advisories: vec![],
        products,
    };
    Ok(HttpResponse::Ok().json(result))
}

#[allow(unused)]
async fn cve_details(
    app_state: web::Data<AppState>,
    guac: web::Data<GuacService>,
    id: web::Path<String>,
    access_token: BearerAuth,
    collectorist: web::Data<CollectoristService>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let id = id.into_inner();

    let provider = BearerTokenProvider {
        token: access_token.token().to_string(),
    };

    Ok(HttpResponse::Ok().json(build_cve_details(&app_state, &guac, provider, id, &collectorist, &v11y).await?))
}

async fn build_cve_details<P>(
    app: &AppState,
    _guac: &GuacService,
    provider: P,
    cve_id: String,
    collectorist: &CollectoristService,
    v11y: &V11yService,
) -> Result<CveDetails, Error>
where
    P: TokenProvider,
{
    collectorist.trigger_vulnerability(&cve_id).await?;
    let details = v11y.fetch_by_alias(&cve_id).await?;

    log::info!("Details: {details:#?}");

    // fetch from index

    let q = format!(r#"cve:"{cve_id}""#);
    let advisories = app.search_vex(&q, 0, 1024, Default::default(), &provider).await?.result;

    let advisory_ids: BTreeSet<String> = advisories
        .into_iter()
        .map(|advisory| advisory.document.advisory_id)
        .collect();

    let mut products = BTreeMap::<&str, BTreeSet<String>>::new();
    let mut advisories = vec![];

    for id in advisory_ids {
        let stream = app.get_vex(&id, &provider).await?;
        let x: BytesMut = stream.try_collect().await?;

        let csaf: Csaf = serde_json::from_slice(&x)?;

        for vuln in csaf
            .vulnerabilities
            .iter()
            .flatten()
            .filter(|vuln| vuln.cve.as_ref().map(|cve| cve == &cve_id).unwrap_or_default())
        {
            if let Some(product_status) = &vuln.product_status {
                extend_products(&csaf, &product_status.fixed, &mut products, "fixed");
                extend_products(&csaf, &product_status.first_fixed, &mut products, "first_fixed");
                extend_products(&csaf, &product_status.first_affected, &mut products, "first_affected");
                extend_products(&csaf, &product_status.known_affected, &mut products, "known_affected");
                extend_products(
                    &csaf,
                    &product_status.known_not_affected,
                    &mut products,
                    "known_not_affected",
                );
                extend_products(&csaf, &product_status.last_affected, &mut products, "last_affected");
                extend_products(&csaf, &product_status.recommended, &mut products, "recommended");
                extend_products(
                    &csaf,
                    &product_status.under_investigation,
                    &mut products,
                    "under_investigation",
                );
            }
        }

        advisories.push(AdvisoryOverview {
            id,
            title: csaf.document.title,
        })
    }

    Ok(CveDetails {
        id: cve_id,
        // products: products
        //     .into_iter()
        //     .map(|(k, v)| (k.to_string(), v.into_iter().collect()))
        //     .collect(),
        products: BTreeMap::new(),
        advisories,
        details,
    })
}

fn extend_products<'a>(
    csaf: &Csaf,
    products: &Option<Vec<ProductIdT>>,
    target: &mut BTreeMap<&'a str, BTreeSet<String>>,
    key: &'a str,
) {
    let result = collect_products(csaf, products);
    if !result.is_empty() {
        target.entry(key).or_default().extend(result);
    }
}

fn collect_products(csaf: &Csaf, products: &Option<Vec<ProductIdT>>) -> Vec<String> {
    let mut result = HashSet::new();

    for product in products.iter().flatten() {
        // add a possible main product
        add_product(csaf, product, &mut result);
        // add products by reference
        for rel in find_product_relations(csaf, &product.0) {
            add_product(csaf, &rel.relates_to_product_reference, &mut result);
        }
    }

    Vec::from_iter(result)
}

fn add_product(csaf: &Csaf, product: &ProductIdT, result: &mut HashSet<String>) {
    let product = trace_product(csaf, &product.0);
    if let Some(product) = product.last() {
        result.insert(product.name.clone());
    }
}
