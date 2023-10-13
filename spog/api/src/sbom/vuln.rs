use crate::error::Error;
use crate::guac::service::GuacService;
use crate::server::{AppState, ResponseError};
use crate::service::v11y::V11yService;
use actix_web::cookie::time;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bombastic_model::data::SBOM;
use bytes::{BufMut, BytesMut};
use cve::Cve;
use futures::stream::iter;
use futures::{StreamExt, TryStreamExt};
use packageurl::PackageUrl;
use serde_json::Value;
use spdx_rs::models::{PackageInformation, SPDX};
use spog_model::prelude::SbomReport;
use spog_model::vuln::SbomReportVulnerability;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use tracing::instrument;
use trustification_auth::client::TokenProvider;
use trustification_common::error::ErrorInformation;
use v11y_client::{ScoreType, Severity, Vulnerability};

#[derive(Debug, serde::Deserialize)]
pub struct GetParams {
    pub id: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/sbom/vulnerabilities",
    responses(
        (status = 200, description = "Package was found"),
        (status = NOT_FOUND, description = "Package was not found")
    ),
    params(
        ("id" = String, Path, description = "Id of package to fetch"),
    )
)]
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
    // avoid getting the full SBOM, but the query fields only
    let mut stream = state.get_sbom(id, access_token).await?;
    let mut sbom = BytesMut::new();

    while let Some(data) = stream.next().await {
        sbom.put(data?);
    }

    let sbom = SBOM::parse(&sbom).map_err(|err| Error::Generic(format!("Unable to parse SBOM: {err}")))?;
    let (name, version, created, analyze) = match sbom {
        SBOM::SPDX(spdx) => {
            let (analyze, num) = analyze(guac, &spdx).await?;

            // get the main packages
            let main = find_main(&spdx);
            // find a single version (if possible)
            let version: Vec<_> = main.iter().flat_map(|pi| &pi.package_version).collect();
            let version = match version.len() {
                1 => Some(version[0].to_string()),
                _ => None,
            };

            let name = spdx.document_creation_information.document_name;
            let created = time::OffsetDateTime::from_unix_timestamp(
                spdx.document_creation_information.creation_info.created.timestamp(),
            )
            .ok();

            log::info!("SBOM report (in: {num} packages) - out: {} {analyze:?}", analyze.len());

            (name, version, created, analyze)
        }
        _ => return Err(Error::Generic("Unsupported format".to_string())),
    };

    // FIXME: mock data
    /*
    let analyze = AnalyzeResponse {
        vulnerabilities: vec![
            mock_vuln("CVE-0000-0001", "Weird one", Some(0.0)),
            mock_vuln("CVE-0000-0002", "Passt schon", Some(0.1)),
            mock_vuln("CVE-0000-0003", "Foo bar", Some(7.5)),
            mock_vuln("CVE-0000-0004", "Bar baz", Some(3.5)),
            mock_vuln("CVE-0000-0005", "Baz foo", Some(4.5)),
            mock_vuln("CVE-0000-0006", "Boom!", Some(9.5)),
            mock_vuln("CVE-0000-0007", "Alles kaputt", Some(10.0)),
            mock_vuln("CVE-0000-0008", "Unsure", None),
        ],
        affected: {
            let map = HashMap::new();
            map
        },
    };*/

    let details = iter(analyze)
        .map(|(id, _packages)| async move {
            // FIXME: need to provide packages to entry
            let cve: cve::Cve = match v11y.fetch(&id).await?.or_status_error_opt().await? {
                Some(cve) => cve.json().await?,
                None => return Ok(None),
            };

            let score = get_score(&cve);
            Ok(Some(SbomReportVulnerability {
                id: cve.id().to_string(),
                description: "".to_string(),
                score,
                published: cve.common_metadata().date_published.map(|t| t.assume_utc()),
                updated: cve.common_metadata().date_updated.map(|t| t.assume_utc()),
            }))
        })
        .buffer_unordered(4)
        .try_filter_map(|r| async move { Ok::<_, Error>(r) })
        .try_collect::<Vec<_>>()
        .await?;

    let summary = summarize_vulns(&details).into_iter().collect();

    Ok(Some(SbomReport {
        name,
        version,
        created,
        summary,
        details,
    }))
}

#[allow(unused)]
fn mock_vuln(id: &str, summary: &str, severity: Option<f32>) -> Vulnerability {
    Vulnerability {
        id: id.to_string(),
        summary: summary.to_string(),
        details: "".to_string(),
        origin: "mock".to_string(),

        published: chrono::Utc::now(),
        modified: chrono::Utc::now(),

        aliases: vec![],
        related: vec![],
        references: vec![],
        affected: vec![],
        withdrawn: None,
        severities: severity
            .into_iter()
            .map(|score| Severity {
                score,
                r#type: ScoreType::Cvss3,
                source: "mock".to_string(),
                additional: None,
            })
            .collect(),
    }
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

fn get_score(cve: &cve::Cve) -> Option<f32> {
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

    for m in &p.containers.cna.metrics {
        if let Some(m) = m.cvss_v3_1.as_ref().and_then(score) {
            v3_1 = Some(m);
        } else if let Some(m) = m.cvss_v3_0.as_ref().and_then(score) {
            v3_0 = Some(m);
        }
    }

    v3_1.or(v3_0)
}

/// Collect a summary of count, based on CVSS v3 severities
fn summarize_vulns<'a>(
    vulnerabilities: impl IntoIterator<Item = &'a SbomReportVulnerability>,
) -> BTreeMap<Option<cvss::Severity>, usize> {
    let mut result = BTreeMap::new();

    for v in vulnerabilities.into_iter() {
        let score = v.score.map(into_severity);
        *result.entry(score).or_default() += 1;
    }

    result
}

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

/// Extract all purls which are referenced by "document describes"
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

#[instrument(skip(guac, sbom), ret, err)]
async fn analyze(guac: &GuacService, sbom: &SPDX) -> Result<(BTreeMap<String, BTreeSet<String>>, usize), Error> {
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    let mut num = 0;

    let purls = sbom.package_information.iter().flat_map(|pi| {
        pi.external_reference
            .iter()
            .filter_map(|er| match er.reference_type == "purl" {
                true => Some(&er.reference_locator),
                false => None,
            })
    });

    for purl_str in purls {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            num += 1;
            let cert = guac.certify_vuln(purl).await?;
            log::debug!("Cert ({purl_str}): {cert:?}");

            for vuln in cert {
                for vuln_id in vuln.vulnerability.vulnerability_ids {
                    result
                        .entry(vuln_id.vulnerability_id)
                        .or_default()
                        .insert(purl_str.clone());
                }
            }
        }
    }

    Ok((result, num))
}

#[cfg(test)]
mod test {
    use super::*;
    use exhort_model::AnalyzeResponse;

    fn test_data() -> AnalyzeResponse {
        AnalyzeResponse {
            vulnerabilities: vec![
                mock_vuln("CVE-0000-0001", "Weird one", Some(0.0)),
                mock_vuln("CVE-0000-0002", "Passt schon", Some(0.1)),
                mock_vuln("CVE-0000-0003", "Foo bar", Some(7.5)),
                mock_vuln("CVE-0000-0004", "Bar baz", Some(3.5)),
                mock_vuln("CVE-0000-0005", "Baz foo", Some(4.5)),
                mock_vuln("CVE-0000-0006", "Boom!", Some(9.5)),
                mock_vuln("CVE-0000-0007", "Alles kaputt", Some(10.0)),
                mock_vuln("CVE-0000-0008", "Unsure", None),
            ],
            affected: Default::default(),
        }
    }

    #[test]
    fn serialize_summary() {
        let analyze = test_data();
        let result: AnalyzeResponse = serde_json::from_value(serde_json::to_value(&analyze).unwrap()).unwrap();

        assert_eq!(result.vulnerabilities.len(), analyze.vulnerabilities.len());
    }
}
