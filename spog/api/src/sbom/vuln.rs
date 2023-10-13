use crate::error::Error;
use crate::server::AppState;
use actix_web::cookie::time;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::{web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use bombastic_model::data::SBOM;
use bytes::{BufMut, BytesMut};
use exhort_model::AnalyzeResponse;
use futures::StreamExt;
use spdx_rs::models::{PackageInformation, SPDX};
use spog_model::prelude::SbomReport;
use spog_model::vuln::SbomReportVulnerability;
use std::collections::{BTreeMap, HashMap};
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
    web::Query(GetParams { id }): web::Query<GetParams>,
    access_token: Option<BearerAuth>,
) -> actix_web::Result<HttpResponse> {
    if let Some(result) = process_get_vulnerabilities(&state, &access_token, &id).await? {
        Ok(HttpResponse::Ok().json(result))
    } else {
        Ok(HttpResponse::NotFound().json(ErrorInformation {
            error: "NoPackageInformation".to_string(),
            message: "The selected SBOM did not contain any packages describing its content".to_string(),
            details: String::new(),
        }))
    }
}

#[instrument(skip(state, access_token), err)]
async fn process_get_vulnerabilities(
    state: &AppState,
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
    let (name, version, created, purls) = match sbom {
        SBOM::SPDX(spdx) => {
            let main = find_main(&spdx);

            if main.is_empty() {
                return Ok(None);
            }

            let purls: Vec<_> = main.iter().flat_map(|pi| map_purls(pi)).collect();
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

            (name, version, created, purls)
        }
        _ => return Err(Error::Generic("Unsupported format".to_string())),
    };

    log::debug!("Requesting report for {} packages", purls.len());

    let analyze = match state.analyze_sbom(purls, access_token).await? {
        Some(analyze) => analyze,
        None => return Ok(None),
    };

    log::debug!("SBOM report: {analyze:#?}");

    // FIXME: mock data
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
    };

    let summary = summarize_vulns(&analyze).into_iter().collect();

    let details = analyze
        .vulnerabilities
        .into_iter()
        .map(|v| {
            let score = get_score(&v);
            SbomReportVulnerability {
                id: v.id,
                description: v.summary,
                score,
                published: OffsetDateTime::from_unix_timestamp(v.published.timestamp()).ok(),
                updated: OffsetDateTime::from_unix_timestamp(v.modified.timestamp()).ok(),
            }
        })
        .collect();

    Ok(Some(SbomReport {
        name,
        version,
        created,
        summary,
        details,
    }))
}

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

fn get_score(v: &Vulnerability) -> Option<f32> {
    let mut v2 = None;
    let mut v3 = None;
    let mut v4 = None;

    for s in &v.severities {
        match s.r#type {
            ScoreType::Cvss2 => v2 = Some(s.score),
            ScoreType::Cvss3 => v3 = Some(s.score),
            ScoreType::Cvss4 => v4 = Some(s.score),
            _ => {}
        }
    }

    v4.or(v3).or(v2)
}

/// Collect a summary of count, based on CVSS v3 severities
fn summarize_vulns(response: &AnalyzeResponse) -> BTreeMap<Option<cvss::Severity>, usize> {
    let mut result = BTreeMap::new();

    for r in &response.vulnerabilities {
        let score = get_score(r).map(into_severity);
        *result.entry(score).or_default() += 1;
    }

    result
}

fn find_main<'a>(spdx: &'a SPDX) -> Vec<&'a PackageInformation> {
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
fn map_purls<'a>(pi: &'a PackageInformation) -> impl IntoIterator<Item = String> + 'a {
    pi.external_reference.iter().filter_map(|er| {
        if er.reference_type == "purl" {
            Some(er.reference_locator.clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;

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
            affected: {
                let map = HashMap::new();
                map
            },
        }
    }

    #[test]
    fn serialize_summary() {
        let analyze = test_data();
        let result: AnalyzeResponse = serde_json::from_value(serde_json::to_value(&analyze).unwrap()).unwrap();

        assert_eq!(result.vulnerabilities.len(), analyze.vulnerabilities.len());
    }

    #[test]
    fn summarize() {
        let analyze = test_data();
        let sum = summarize_vulns(&analyze);

        assert_eq!(sum.len(), 6);
    }
}
