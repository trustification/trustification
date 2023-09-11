use crate::guac::service::GuacService;
use crate::server::{AppState, Error};
use crate::service::collectorist::CollectoristService;
use crate::service::v11y::V11yService;
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::BytesMut;
use csaf::definitions::ProductIdT;
use csaf::Csaf;
use futures::TryStreamExt;
use spog_model::csaf::{find_product_relations, trace_product};
use spog_model::cve::{AdvisoryOverview, CveDetails};
use spog_model::prelude::Details;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::client::{BearerTokenProvider, TokenProvider};
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/cve/{id}").wrap(new_auth!(auth)).to(cve_details));
    }
}

async fn cve_details(
    app_state: web::Data<AppState>,
    guac: web::Data<GuacService>,
    id: web::Path<String>,
    access_token: BearerAuth,
    collectorist: web::Data<CollectoristService>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let id = id.into_inner();

    log::info!("Access token: {}", access_token.token());

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
    // TODO: trigger collectorist
    // TODO: fetch from v11y

    collectorist.trigger_vulnerability(&cve_id).await?;
    let mut details = v11y.fetch(&cve_id).await?;

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

    log::info!("Details: {details:#?}");

    let details = details
        .pop()
        .map(|vuln| Details {
            summary: vuln.summary,
            details: vuln.details,
        })
        .unwrap_or_default();

    Ok(CveDetails {
        id: cve_id,
        products: products
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_iter().collect()))
            .collect(),
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
