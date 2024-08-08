use crate::app_state::AppState;
use crate::search;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::{Deserialize, Serialize};
use spog_model::search::SbomSummary;
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Vulnerabilities {
    none: usize,
    low: usize,
    medium: usize,
    high: usize,
    critical: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomVulnerabilitySummary {
    sbom_id: String,
    sbom_name: String,
    vulnerabilities: Vulnerabilities,
}

pub async fn sboms_with_vulnerability_summary() -> actix_web::Result<HttpResponse> {
    let mut summary: Vec<SbomVulnerabilitySummary> = vec![];
    let vulns1: Vulnerabilities = Vulnerabilities {
        none: 3,
        low: 12,
        medium: 8,
        high: 5,
        critical: 1,
    };
    let vulns2: Vulnerabilities = Vulnerabilities {
        none: 1,
        low: 8,
        medium: 17,
        high: 9,
        critical: 0,
    };
    let vulns3: Vulnerabilities = Vulnerabilities {
        none: 18,
        low: 20,
        medium: 6,
        high: 8,
        critical: 4,
    };
    let sbom1: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom1_id".into(),
        sbom_name: "sbom1".into(),
        vulnerabilities: vulns1,
    };
    let sbom2: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom2_id".into(),
        sbom_name: "sbom2".into(),
        vulnerabilities: vulns2,
    };
    let sbom3: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom3_id".into(),
        sbom_name: "sbom3".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom4: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom4_id".into(),
        sbom_name: "sbom4".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom5: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom5_id".into(),
        sbom_name: "sbom5".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom6: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom6_id".into(),
        sbom_name: "sbom6".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom7: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom7_id".into(),
        sbom_name: "sbom7".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom8: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom8_id".into(),
        sbom_name: "sbom8".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom9: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom9_id".into(),
        sbom_name: "sbom9".into(),
        vulnerabilities: vulns3.clone(),
    };
    let sbom10: SbomVulnerabilitySummary = SbomVulnerabilitySummary {
        sbom_id: "sbom10_id".into(),
        sbom_name: "sbom10".into(),
        vulnerabilities: vulns3.clone(),
    };

    summary.push(sbom1);
    summary.push(sbom2);
    summary.push(sbom3);
    summary.push(sbom4);
    summary.push(sbom5);
    summary.push(sbom6);
    summary.push(sbom7);
    summary.push(sbom8);
    summary.push(sbom9);
    summary.push(sbom10);

    Ok(HttpResponse::Ok().json(summary))
}
