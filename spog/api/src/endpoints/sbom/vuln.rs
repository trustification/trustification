use crate::app_state::{AppState, ResponseError};
use crate::error::Error;
use crate::service::guac::GuacSbomIdentifier;
use crate::service::{guac::GuacService, v11y::V11yService};
use actix_web::cookie::time;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bombastic_model::data::SBOM;
use bytes::BytesMut;
use csaf::document::Category;
use csaf::Csaf;
use cve::Cve;
use futures::stream::iter;
use futures::{stream, StreamExt, TryStreamExt};
use names::Generator;
use packageurl::PackageUrl;
use rand::Rng;
use serde_json::Value;
use spdx_rs::models::{PackageInformation, SPDX};
use spog_model::csaf::has_purl;
use spog_model::prelude::{Remediation, SbomReport, Source, SummaryEntry};
use spog_model::vuln::{Backtrace, SbomReportVulnerability, SourceDetails};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::str::FromStr;
use tracing::{info_span, instrument, Instrument};
use trustification_api::search::SearchOptions;
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
    let sbom: BytesMut = state.get_sbom(id, access_token).await?.try_collect().await?;

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
            let cve: Cve = match v11y.fetch(&id).await?.or_status_error_opt().await? {
                Some(cve) => cve.json().await?,
                None => return Ok(None),
            };
            let score = get_score(&cve);

            let mut sources = HashMap::new();
            sources.insert(Source::Mitre, SourceDetails { score });

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
) -> BTreeMap<Source, BTreeMap<Option<cvss::Severity>, usize>> {
    let mut result = BTreeMap::<Source, BTreeMap<_, _>>::new();

    for v in vulnerabilities.into_iter() {
        for (source, details) in &v.sources {
            let result = result.entry(*source).or_default();
            let score = details.score.map(into_severity);
            *result.entry(score).or_default() += 1;
        }
    }

    result
}

/// Extract all purls which are referenced by "document describes"
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

#[derive(Default)]
pub struct AnalyzeOutcome {
    // CVE to PURLs to remediations
    cve_to_purl: BTreeMap<String, BTreeMap<String, Vec<Remediation>>>,
    // PURL to backtrace
    purl_to_backtrace: BTreeMap<String, BTreeSet<Backtrace>>,
}

/// Analyze by purls
///
/// result(Ok):
///   map(CVE to array(PURL))
///   map(purl to parents(chain of purls))
///   total number of packages found
#[instrument(skip(state, guac, token), err)]
async fn analyze_spdx(
    state: &AppState,
    guac: &GuacService,
    token: &dyn TokenProvider,
    main: &PackageInformation,
) -> Result<AnalyzeOutcome, Error> {
    let version = match &main.package_version {
        Some(version) => version,
        None => {
            return Err(Error::Generic(
                "SBOM's main component is missing the version".to_string(),
            ))
        }
    };

    // find vulnerabilities

    let cve_to_purl = guac
        .find_vulnerability(GuacSbomIdentifier {
            name: &main.package_name,
            version,
        })
        .await?;

    // collect the backtraces

    let purl_to_backtrace = async {
        stream::iter(
            cve_to_purl
                .values()
                .flatten()
                .filter_map(|purl| PackageUrl::from_str(purl).ok()),
        )
        .map(|purl| async move {
            let backtraces = backtrace(guac, &purl).await?.collect::<BTreeSet<_>>();
            Ok::<_, Error>((purl.to_string(), backtraces))
        })
        .buffer_unordered(4)
        .try_collect()
        .await
    }
    .instrument(info_span!("collect backtraces"))
    .await?;

    // get all relevant VEX documents

    let vex = collect_vex(state, token, cve_to_purl.keys()).await?;

    // fill in the remediations

    let cve_to_purl = info_span!("scrape_remediations").in_scope(|| {
        let mut count = 0;

        let result = cve_to_purl
            .into_iter()
            .map(|(cve, purls)| {
                let purls = purls
                    .into_iter()
                    .map(|purl| {
                        let rem = scrape_remediations(&cve, &purl, &vex);
                        count += rem.len();

                        (purl, rem)
                    })
                    .collect::<BTreeMap<String, Vec<Remediation>>>();

                (cve, purls)
            })
            .collect();

        log::debug!("Found {count} remediations");

        result
    });

    // done

    Ok(AnalyzeOutcome {
        cve_to_purl,
        purl_to_backtrace,
    })
}

/// take a PURL, a retrieve all paths towards the main entry point of its SBOM
// FIXME: This needs to be implemented
#[instrument(skip(_guac), err)]
async fn backtrace<'a>(
    _guac: &GuacService,
    _purl: &'a PackageUrl<'a>,
) -> Result<impl Iterator<Item = Backtrace> + 'a, Error> {
    let mut rng = rand::thread_rng();
    let mut names = Generator::default();

    // create some mock data
    let mut result = vec![];

    for _ in 0..rng.gen_range(0..5) {
        let mut trace = vec![];
        for _ in 0..rng.gen_range(1..5) {
            trace.push(
                PackageUrl::new("mock", names.next().unwrap_or_else(|| "mock".to_string()))
                    .map(|purl| purl.to_string())
                    .unwrap_or_else(|_| "pkg://mock/failed".to_string())
                    .to_string(),
            );
        }
        result.push(Backtrace(trace));
    }

    Ok(result.into_iter())
}

/// take a set of CVE id and fetch their related CSAF documents
#[instrument(skip_all, fields(num_ids), err)]
async fn collect_vex<'a>(
    state: &AppState,
    token: &dyn TokenProvider,
    ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<HashMap<String, Vec<Rc<Csaf>>>, Error> {
    let ids = ids.into_iter();
    let (_, num_ids) = ids.size_hint();
    tracing::Span::current().record("num_ids", num_ids);

    let ids = ids.filter(|id| !id.as_ref().is_empty());

    // a stream of chunked queries
    let cves = stream::iter(ids)
        // request in chunks of 10
        .ready_chunks(SEARCH_CHUNK_SIZE)
        .map(Ok)
        .and_then(|ids| async move {
            let q = ids
                .iter()
                .map(|id| format!(r#"cve:"{}""#, id.as_ref()))
                .collect::<Vec<_>>()
                .join(" OR ");

            // lookup documents (limit to 1.000, which should be reasonable)
            let result = state.search_vex(&q, 0, 1000, SearchOptions::default(), token).await?;

            Ok::<HashSet<_>, Error>(result.result.into_iter().map(|hit| hit.document.advisory_id).collect())
        });

    // flatten the result stream
    let cves: HashSet<String> = cves.try_collect::<Vec<_>>().await?.into_iter().flatten().collect();

    // now fetch the documents and sort them in the result map
    let result: HashMap<String, Vec<_>> = stream::iter(cves)
        .map(|id| async move {
            let doc: BytesMut = state.get_vex(&id, token).await?.try_collect().await?;

            let mut result = Vec::new();

            if let Ok(doc) = serde_json::from_slice::<Csaf>(&doc) {
                let doc = Rc::new(doc);
                if let Some(v) = &doc.vulnerabilities {
                    for v in v {
                        if let Some(cve) = v.cve.clone() {
                            result.push((cve, doc.clone()))
                        }
                    }
                }
            }

            Ok::<_, Error>(result)
        })
        // fetch parallel
        .buffer_unordered(PARALLEL_FETCH_VEX)
        // fold them into a single result
        .try_fold(HashMap::<String, Vec<Rc<Csaf>>>::new(), |mut acc, x| async move {
            for (id, docs) in x {
                acc.entry(id).or_default().push(docs);
            }
            Ok(acc)
        })
        .await?;

    Ok(result)
}

/// from a set of relevant VEXes, fetch the matching remediations for this PURL
fn scrape_remediations(id: &str, purl: &str, vex: &HashMap<String, Vec<Rc<Csaf>>>) -> Vec<Remediation> {
    let mut result = vec![];

    // iterate over all documents
    for vex in vex.get(id).iter().flat_map(|v| *v) {
        if vex.document.category != Category::Vex {
            continue;
        }

        // iterate over all vulnerabilities of the document
        for v in vex
            .vulnerabilities
            .iter()
            .flatten()
            .filter(|v| v.cve.as_deref() == Some(id))
        {
            // now convert all the remediations
            for r in v.remediations.iter().flatten() {
                // only add remediations matching the purl
                if !has_purl(vex, &r.product_ids, purl) {
                    continue;
                }

                result.push(Remediation {
                    details: r.details.clone(),
                })
            }
        }
    }

    result
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_scrape_remediations() {
        let csaf = include_bytes!("../../../../example-data/cve-2023-22998.json");
        let csaf: Csaf = serde_json::from_slice(csaf).unwrap();

        let mut vex = HashMap::new();
        vex.insert("CVE-2023-22998".to_string(), vec![Rc::new(csaf)]);
        let rem = scrape_remediations(
            "CVE-2023-22998",
            "pkg:rpm/redhat/kernel-rt-modules-extra@5.14.0-284.11.1.rt14.296.el9_2?arch=x86_64",
            &vex,
        );

        assert_eq!(rem, vec![Remediation{
            details: "Before applying this update, make sure all previously released errata\nrelevant to your system have been applied.\n\nFor details on how to apply this update, refer to:\n\nhttps://access.redhat.com/articles/11258".to_string()
        }]);
    }
}
