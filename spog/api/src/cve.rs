use crate::{
    app_state::AppState, error::Error, guac::service::GuacService, search, service::collectorist::CollectoristService,
    service::v11y::V11yService,
};
use actix_web::{
    web::{self, ServiceConfig},
    HttpResponse, HttpResponseBuilder,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bytes::BytesMut;
use csaf::definitions::ProductIdT;
use csaf::Csaf;
use futures::{stream, TryStreamExt};
use spog_model::{
    csaf::{find_product_relations, trace_product},
    cve::{AdvisoryOverview, CveDetails, CveSearchDocument},
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::{SearchOptions, SearchResult};
use trustification_auth::{
    authenticator::Authenticator,
    client::{BearerTokenProvider, TokenProvider},
};
use trustification_infrastructure::new_auth;
use v11y_client::search::{SearchDocument, SearchHit};

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::scope("/api/v1/cve")
                .wrap(new_auth!(auth))
                .service(web::resource("").to(cve_search))
                .service(web::resource("/{id}").to(cve_get))
                .service(web::resource("/{id}/related-products").to(cve_related_product)),
        );
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/cve",
    responses(
        (status = OK, description = "Search was performed successfully", body = SearchResultCve),
    ),
    params(search::QueryParams)
)]
#[instrument(skip(v11y, state), err)]
async fn cve_search(
    web::Query(params): web::Query<search::QueryParams>,
    v11y: web::Data<V11yService>,
    state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let SearchResult { result, total } = v11y.search(params).await.map_err(Error::V11y)?;

    // enrich the results with counts of relations
    let result: Vec<_> = stream::iter(result.into_iter().map(Ok::<_, Error>))
        .and_then(move |hit: SearchHit<SearchDocument>| {
            let state = state.clone();
            async move {
                let related_advisories = count_related_advisories(&state, &hit.document.id).await?;
                let related_products = count_related_products(&hit.document.id).await?;
                Ok(hit.map(|document| CveSearchDocument {
                    document,
                    related_advisories,
                    related_products,
                }))
            }
        })
        .try_collect()
        .await?;

    Ok(HttpResponse::Ok().json(SearchResult { total, result }))
}

/// return the number of related advisories for a CVE
#[instrument(skip(state), err, ret)]
async fn count_related_advisories(state: &AppState, cve: &str) -> Result<usize, Error> {
    let options = SearchOptions {
        summaries: false,
        ..Default::default()
    };
    let result = state
        .search_vex(&format!(r#"cve:"{}""#, cve), 0, 1000, options, &*state.provider)
        .await?;
    Ok(result.total)
}

/// return the number of related products for a CVE
async fn count_related_products(_cve: &str) -> Result<usize, Error> {
    // FIXME: implemented by guac
    Ok(0)
}

#[utoipa::path(
    get,
    path = "/api/v1/cve/{id}",
    responses(
        (status = OK, description = "Search was performed successfully", body = SearchResultCve),
    ),
    params(
        ("id" = String, Path, description = "The CVE to retrieve"),
    )
)]
#[instrument(skip(v11y), err)]
async fn cve_get(id: web::Path<String>, v11y: web::Data<V11yService>) -> actix_web::Result<HttpResponse> {
    let id = id.into_inner();

    let response = v11y.fetch(&id).await?;

    Ok(HttpResponseBuilder::new(response.status()).streaming(response.bytes_stream()))
}

async fn cve_related_product(
    _app_state: web::Data<AppState>,
    guac: web::Data<GuacService>,
    id: web::Path<String>,
    _access_token: BearerAuth,
    _collectorist: web::Data<CollectoristService>,
    _v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let id = id.into_inner();

    let result = guac.product_by_cve(id).await?;

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

#[instrument(skip_all, fields(cve_id = % cve_id), err)]
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

    log::debug!("Details: {details:#?}");

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
