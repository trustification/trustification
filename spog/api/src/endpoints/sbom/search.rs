use crate::app_state::AppState;

use crate::error::Error;
use crate::search::QueryParams;
use crate::service::guac::GuacService;

use crate::service::v11y::V11yService;
use crate::{endpoints, search};
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bombastic_model::search::SearchHit;
use cvss::Severity;
use futures::future::join_all;
use spog_model::prelude::{Last10SbomVulnerabilitySummary, Last10SbomVulnerabilitySummaryVulnerabilities};
use spog_model::search::SbomSummary;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::{SearchOptions, SearchResult};
use trustification_auth::client::TokenProvider;

#[utoipa::path(
    get,
    path = "/api/v1/sbom/search",
    responses(
        (status = OK, description = "Search was performed successfully", body = SearchResultSbom),
    ),
    params(
        search::QueryParams,
        SearchOptions,
    )
)]
#[instrument(skip(state, access_token), err)]
pub async fn search(
    state: web::Data<AppState>,
    params: web::Query<search::QueryParams>,
    options: web::Query<SearchOptions>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    let params = params.into_inner();
    log::trace!("Querying SBOM using {}", params.q);
    let data = state
        .search_sbom(
            &params.q,
            params.offset,
            params.limit,
            options.into_inner(),
            &access_token,
        )
        .await?;
    let mut m: Vec<SbomSummary> = Vec::with_capacity(data.result.len());
    for item in data.result {
        let metadata = item.metadata.unwrap_or_default();
        let item = item.document;
        m.push(SbomSummary {
            id: item.id.clone(),
            purl: item.purl,
            name: item.name,
            cpe: item.cpe,
            version: item.version,
            sha256: item.sha256,
            license: item.license,
            snippet: item.snippet,
            classifier: item.classifier,
            supplier: item.supplier.trim_start_matches("Organization: ").to_string(),
            href: format!("/api/v1/sbom?id={}", item.id),
            description: item.description,
            dependencies: item.dependencies,
            vulnerabilities: vec![],
            advisories: None,
            created: item.created,
            metadata,
        });
    }

    let mut result = SearchResult {
        total: Some(data.total),
        result: m,
    };

    // TODO: Use guac to lookup advisories for each sbom!
    search_advisories(state, &mut result.result, &access_token).await;
    Ok(HttpResponse::Ok().json(result))
}

#[instrument(skip_all)]
async fn search_advisories(state: web::Data<AppState>, sboms: &mut Vec<SbomSummary>, provider: &dyn TokenProvider) {
    for sbom in sboms {
        if let Some(q) = sbom.advisories_query() {
            if let Ok(result) = state
                .search_vex(
                    &q,
                    0,
                    100000,
                    SearchOptions {
                        explain: false,
                        metadata: false,
                        summaries: false,
                    },
                    provider,
                )
                .await
            {
                sbom.advisories = Some(result.total as u64);
            }
        }
    }
}

#[instrument(skip(state, v11y, guac, access_token), err)]
pub async fn sboms_with_vulnerability_summary(
    state: web::Data<AppState>,
    access_token: Option<BearerAuth>,
    guac: web::Data<GuacService>,
    v11y: web::Data<V11yService>,
) -> actix_web::Result<HttpResponse> {
    let ten_latest_sboms = state
        .search_sbom(
            "-sort:indexedTimestamp",
            0,
            10,
            SearchOptions {
                explain: false,
                metadata: true,
                summaries: true,
            },
            &access_token,
        )
        .await?;

    // Create a vector of async tasks
    let tasks: Vec<_> = ten_latest_sboms
        .result
        .into_iter()
        .map(|sbom| {
            let v11y = Arc::clone(&v11y);
            let guac = Arc::clone(&guac);
            tokio::task::spawn_local(async move { sbom_vulnerabilities_retrieval(guac, v11y, sbom).await })
        })
        .collect();

    // Await all tasks and collect the results
    log::debug!("start waiting results");
    let results = join_all(tasks).await;
    log::debug!("stop waiting results");

    // Collecting the results in the correct order
    let mut output: Vec<Last10SbomVulnerabilitySummary> = vec![];
    results.into_iter().for_each(|result| match result {
        Ok(inner_result) => match inner_result {
            Ok(summary) => output.push(summary),
            Err(err) => log::warn!("Retrieving vulnerabilities for an SBOM failed due to: {:?}", err),
        },
        Err(err) => {
            log::warn!("Retrieving vulnerabilities for an SBOM failed due to: {:?}", err);
        }
    });

    Ok(HttpResponse::Ok().json(output))
}

#[instrument(skip(v11y, guac, sbom), err)]
async fn sbom_vulnerabilities_retrieval(
    guac: Arc<GuacService>,
    v11y: Arc<V11yService>,
    sbom: SearchHit,
) -> Result<Last10SbomVulnerabilitySummary, Error> {
    // find vulnerabilities
    let cve_to_purl = guac
        .find_vulnerability_by_uid(
            sbom.document.uid.clone().unwrap_or("".to_string()).as_str(),
            Some(0),
            Some(100000),
        )
        .await?;
    log::info!("{:?} {} vulnerabilities found", sbom.document.uid, cve_to_purl.len());

    // fetch CVE details
    let cves = cve_to_purl.keys().cloned().collect::<Vec<String>>();
    let none = &AtomicUsize::new(0);
    let low = &AtomicUsize::new(0);
    let medium = &AtomicUsize::new(0);
    let high = &AtomicUsize::new(0);
    let critical = &AtomicUsize::new(0);
    // query 25 vulnerabilities at time
    let futures = cves.chunks(25).map(|chunk| {
        let v11y = Arc::clone(&v11y);
        async move {
            let q = format!("id:\"{}\"", chunk.join("\" OR id:\""));
            log::debug!("querying for {}", q);
            let query: QueryParams = QueryParams {
                q,
                offset: 0,
                limit: chunk.len(),
            };

            match v11y.search(query).await {
                Ok(SearchResult { result, total }) => {
                    if let Some(1..) = total {
                        result.iter().for_each(|cve| {
                            let score = Option::from(cve.document.cvss3x_score.unwrap_or(0f64) as f32);
                            log::debug!("{} score is {:?}", cve.document.id, score);
                            match endpoints::sbom::vuln::into_severity(cve.document.cvss3x_score.unwrap_or(0f64) as f32)
                            {
                                Severity::None => none.fetch_add(1, Relaxed),
                                Severity::Low => low.fetch_add(1, Relaxed),
                                Severity::Medium => medium.fetch_add(1, Relaxed),
                                Severity::High => high.fetch_add(1, Relaxed),
                                Severity::Critical => critical.fetch_add(1, Relaxed),
                            };
                        })
                    };
                }
                Err(e) => {
                    log::error!("Vulnerabilities search failed due to {:?}", e);
                }
            }
        }
    });
    log::debug!("{:?} Start waiting for futures", sbom.document.uid);
    join_all(futures).await;
    log::debug!("{:?} Stop waiting for futures", sbom.document.uid);

    Ok(Last10SbomVulnerabilitySummary {
        sbom_id: sbom.document.id,
        sbom_name: sbom.document.name,
        vulnerabilities: Last10SbomVulnerabilitySummaryVulnerabilities {
            none: none.load(Relaxed),
            low: low.load(Relaxed),
            medium: medium.load(Relaxed),
            high: high.load(Relaxed),
            critical: critical.load(Relaxed),
        },
    })
}
