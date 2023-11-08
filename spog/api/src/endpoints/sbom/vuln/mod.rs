mod analyze;
mod backtrace;
mod vex;

use crate::app_state::{AppState, ResponseError};
use crate::endpoints::sbom::vuln::analyze::AnalyzeOutcome;
use crate::error::Error;
use crate::service::{guac::GuacService, v11y::V11yService};
use actix_web::cookie::time;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use analyze::analyze_spdx;
use bombastic_model::data::SBOM;
use bytes::BytesMut;
use cve::Cve;
use futures::stream::iter;
use futures::{StreamExt, TryStreamExt};
use serde_json::Value;
use spdx_rs::models::{PackageInformation, SPDX};
use spog_model::{
    prelude::{SbomReport, SummaryEntry},
    vuln::{SbomReportVulnerability, SourceDetails},
};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use tracing::{info_span, instrument, Instrument};
use trustification_auth::client::TokenProvider;
use trustification_common::error::ErrorInformation;
use utoipa::IntoParams;

/// chunk size for finding VEX by CVE IDs
const SEARCH_CHUNK_SIZE: usize = 10;
/// number of parallel fetches for VEX documents
const PARALLEL_FETCH_VEX: usize = 4;

#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct GetParams {
    /// ID of the SBOM to get vulnerabilities for
    pub id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/sbom/vulnerabilities",
    responses(
        (status = OK, description = "Processing succeeded", body = SbomReport),
        (status = NOT_FOUND, description = "SBOM was not found")
    ),
    params(GetParams)
)]
#[instrument(skip(state, v11y, guac, access_token), err)]
pub async fn get_vulnerabilities(
    state: web::Data<AppState>,
    v11y: web::Data<V11yService>,
    guac: web::Data<GuacService>,
    web::Query(GetParams { id }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    if let Some(result) = process_get_vulnerabilities(&state, &v11y, &guac, &access_token, &id).await? {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::NotFound().json(ErrorInformation {
            error: "NoPackageInformation".to_string(),
            message: "The selected SBOM did not contain any packages describing its content".to_string(),
            details: String::new(),
        }))
    }
}

#[instrument(skip(state, guac, v11y, access_token), err)]
async fn process_get_vulnerabilities(
    state: &AppState,
    v11y: &V11yService,
    guac: &GuacService,
    access_token: &dyn TokenProvider,
    id: &str,
) -> Result<Option<SbomReport>, Error> {
    // FIXME: avoid getting the full SBOM, but the search document fields only
    let sbom: BytesMut = state
        .get_sbom(id, access_token)
        .await?
        .try_collect()
        .instrument(info_span!("download SBOM data"))
        .await?;

    let sbom = SBOM::parse(&sbom).map_err(|err| Error::Generic(format!("Unable to parse SBOM: {err}")))?;
    let (name, version, created, analyze, backtraces) = match sbom {
        SBOM::SPDX(spdx) => {
            // get the main packages
            let main = find_main(&spdx);

            let main = match main.as_slice() {
                [main] => main,
                [] => {
                    return Err(Error::Generic(
                        r#"SBOM has no "document describes" entries. Unable to analyze."#.to_string(),
                    ))
                }
                _ => {
                    return Err(Error::Generic(format!(
                        r#"SBOM has more than one "document describes" entry (number of entries: {})."#,
                        main.len()
                    )))
                }
            };

            let AnalyzeOutcome {
                cve_to_purl,
                purl_to_backtrace,
            } = analyze_spdx(state, guac, access_token, main).await?;

            // find a single version (if possible)
            let version = main.package_version.clone();
            let name = spdx.document_creation_information.document_name;
            let created = time::OffsetDateTime::from_unix_timestamp(
                spdx.document_creation_information.creation_info.created.timestamp(),
            )
            .ok();

            (name, version, created, cve_to_purl, purl_to_backtrace)
        }
        _ => return Err(Error::Generic("Unsupported format".to_string())),
    };

    // fetch CVE details

    let details = iter(analyze)
        .map(|(id, affected_packages)| async move {
            // FIXME: need to provide packages to entry
            let cve: Cve = match v11y.fetch_cve(&id).await?.or_status_error_opt().await? {
                Some(cve) => cve.json().await?,
                None => return Ok(None),
            };
            let score = get_score(&cve);

            let mut sources = HashMap::new();
            sources.insert("mitre".to_string(), SourceDetails { score });

            Ok(Some(SbomReportVulnerability {
                id: cve.id().to_string(),
                description: get_description(&cve),
                sources,
                published: cve.common_metadata().date_published.map(|t| t.assume_utc()),
                updated: cve.common_metadata().date_updated.map(|t| t.assume_utc()),
                affected_packages,
            }))
        })
        .buffer_unordered(4)
        // filter out missing ones
        .try_filter_map(|r| async move { Ok::<_, Error>(r) })
        .try_collect::<Vec<_>>()
        .await?;

    // summarize scores

    let summary = summarize_vulns(&details)
        .into_iter()
        .map(|(source, counts)| {
            (
                source,
                counts
                    .into_iter()
                    .map(|(severity, count)| SummaryEntry { severity, count })
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    // done

    Ok(Some(SbomReport {
        name,
        version,
        created,
        summary,
        details,
        backtraces,
    }))
}

fn into_severity(score: f32) -> cvss::Severity {
    if score >= 9.0 {
        cvss::Severity::Critical
    } else if score >= 7.0 {
        cvss::Severity::High
    } else if score >= 4.0 {
        cvss::Severity::Medium
    } else if score > 0.0 {
        cvss::Severity::Low
    } else {
        cvss::Severity::None
    }
}

/// get the description
///
/// We scan for the first description matching "en" or an empty string, as "en" is default.
///
// FIXME: We should consider other langauges as well, like a language priorities list.
fn get_description(cve: &Cve) -> Option<String> {
    let desc = match cve {
        Cve::Published(cve) => {
            if let Some(title) = cve.containers.cna.title.clone() {
                return Some(title);
            }

            &cve.containers.cna.descriptions
        }
        Cve::Rejected(cve) => &cve.containers.cna.rejected_reasons,
    };

    desc.iter()
        .filter_map(|d| {
            let lang = &d.language;
            if lang.is_empty() || lang.starts_with("en") {
                Some(d.value.clone())
            } else {
                None
            }
        })
        .next()
}

/// get the CVSS score as a plain number
fn get_score(cve: &Cve) -> Option<f32> {
    let p = match cve {
        Cve::Published(p) => p,
        Cve::Rejected(_) => return None,
    };

    let score = |value: &Value| {
        value["vectorString"]
            .as_str()
            .and_then(|s| cvss::v3::Base::from_str(s).ok())
            .map(|base| base.score().value() as f32)
    };

    let mut v3_1 = None;
    let mut v3_0 = None;
    let mut v2_0 = None;

    for m in &p.containers.cna.metrics {
        if let Some(m) = m.cvss_v3_1.as_ref().and_then(score) {
            v3_1 = Some(m);
        } else if let Some(m) = m.cvss_v3_0.as_ref().and_then(score) {
            v3_0 = Some(m);
        } else if let Some(m) = m.cvss_v2_0.as_ref().and_then(score) {
            v2_0 = Some(m);
        }
    }

    // FIXME: we need to provide some indication what score version this was

    v3_1.or(v3_0).or(v2_0)
}

/// Collect a summary of count, based on CVSS v3 severities
fn summarize_vulns<'a>(
    vulnerabilities: impl IntoIterator<Item = &'a SbomReportVulnerability>,
) -> BTreeMap<String, BTreeMap<Option<cvss::Severity>, usize>> {
    let mut result = BTreeMap::<String, BTreeMap<_, _>>::new();

    for v in vulnerabilities.into_iter() {
        for (source, details) in &v.sources {
            let result = result.entry(source.clone()).or_default();
            let score = details.score.map(into_severity);
            *result.entry(score).or_default() += 1;
        }
    }

    result
}

/// Extract all purls which are referenced by "document describes"
#[instrument(skip_all)]
fn find_main(spdx: &SPDX) -> Vec<&PackageInformation> {
    let mut main = vec![];
    for desc in &spdx.document_creation_information.document_describes {
        for pi in &spdx.package_information {
            if &pi.package_spdx_identifier == desc {
                main.push(pi);
            }
        }
    }

    main
}

/// map package information to it's purls
#[allow(unused)]
fn map_purls(pi: &PackageInformation) -> impl IntoIterator<Item = String> + '_ {
    pi.external_reference.iter().filter_map(|er| {
        if er.reference_type == "purl" {
            Some(er.reference_locator.clone())
        } else {
            None
        }
    })
}
