use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use guac::client::intrinsic::certify_vuln::ScanMetadataInput;
use guac::client::intrinsic::vuln_equal::VulnEqualInputSpec;
use guac::client::intrinsic::vuln_metadata::{VulnerabilityMetadataInputSpec, VulnerabilityScoreType};
use guac::client::intrinsic::vulnerability::VulnerabilityInputSpec;
use packageurl::PackageUrl;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use collector_client::{CollectPackagesRequest, CollectPackagesResponse};
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::CollectorSnyk;
use trustification_infrastructure::{new_auth, MainContext};
use v11y_client::Vulnerability;

use crate::client::SnykClient;
use crate::rewrite::rewrite;
use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    tags(
        (name = "collector-snyk")
    ),
    paths(
        crate::server::collect_packages,
    )
)]
pub struct ApiDoc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("snyk error {0}")]
    Snyk(crate::client::Error),
}

impl ResponseError for Error {}

impl From<crate::client::Error> for Error {
    fn from(inner: crate::client::Error) -> Self {
        Self::Snyk(inner)
    }
}

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorSnyk>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::from_str(&http.bind_addr)?, *http.bind_port);
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    HttpServerBuilder::try_from(http)?
        .authorizer(authorizer)
        .metrics(context.metrics.registry().clone(), "collector_snyk")
        .configure(move |svc| {
            svc.app_data(web::Data::from(state.clone()));
            config(svc, authenticator.clone());
        })
        .listen(listener)
        .run()
        .await
}

pub fn config(cfg: &mut web::ServiceConfig, auth: Option<Arc<Authenticator>>) {
    cfg.service(web::scope("/api/v1").wrap(new_auth!(auth)).service(collect_packages))
        .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

#[utoipa::path(
    post,
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("packages")]
pub async fn collect_packages(
    request: web::Json<CollectPackagesRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, Error> {
    let snyk = SnykClient::new(&state.snyk_org_id, &state.snyk_token);

    // we collect soft errors and proceed as much as possible.
    let mut collected_snyk_errors = Vec::new();
    let mut collected_guac_errors = Vec::new();
    let mut collected_v11y_errors = Vec::new();

    let mut vulns: Vec<v11y_client::Vulnerability> = Vec::new();

    let mut gathered_purls = HashMap::new();

    for original_purl in &request.purls {
        // rewrite the purl for Snyk, due to `redhat` vs `rhel` and `?distro` qualifier.
        let purl = rewrite(original_purl);

        // the rewrite might fail for one purl, so we check.
        match purl {
            Ok(purl) => {
                log::info!("check {purl}");
                let snyk_response = snyk.issues(&purl).await;

                match snyk_response {
                    Ok(issues) => {
                        log::info!("issues {}", issues.len());
                        // Snyk replied with at least a moderately okay response, proceed.
                        if let Ok(purl) = PackageUrl::from_str(original_purl) {
                            if !issues.is_empty() {
                                // Since at least one issue was discovered, we need to
                                // ensure that GUAC knows about the package so we can
                                // link it to these issues later. Additionally, we add
                                // it to the response set for the collectorist to continue
                                // tracking as it sees fit.

                                if let Err(err) = state.guac_client.intrinsic().ingest_package(&purl.into()).await {
                                    collected_guac_errors.push(err.to_string());
                                }
                            }

                            for issue in &issues {
                                // A single Synk issue may represent multiple problems
                                // and we dig in because the problem `id` is the ID we want
                                // to track within GUAC.
                                //
                                // Add each of the problem IDs into GUAC so we can subsequently
                                // wire them up to the previous packages we ingested.

                                let mut ids = Vec::new();

                                let snyk_vuln_input_spec = VulnerabilityInputSpec {
                                    r#type: "snyk".to_string(),
                                    vulnerability_id: issue.attributes.key.clone(),
                                };

                                ids.push(issue.attributes.key.clone());
                                // Ingest the root Snyk issue `key`
                                // We will subsequently ingest some aliases around it.

                                if let Err(err) = state
                                    .guac_client
                                    .intrinsic()
                                    .ingest_vulnerability(&snyk_vuln_input_spec)
                                    .await
                                {
                                    collected_guac_errors.push(err.to_string())
                                }

                                if let Ok(purl) = PackageUrl::from_str(original_purl) {
                                    // Ingest the relationship between each the snyk issue ID
                                    // and the purl it's associated with.
                                    if let Err(err) = state
                                        .guac_client
                                        .intrinsic()
                                        .ingest_certify_vuln(
                                            &purl.into(),
                                            &snyk_vuln_input_spec,
                                            &ScanMetadataInput {
                                                db_uri: "https://api.snyk.io/".to_string(),
                                                db_version: "1.0".to_string(),
                                                scanner_uri: "https://trustification.io/".to_string(),
                                                scanner_version: "1.0".to_string(),
                                                time_scanned: Default::default(),
                                                origin: "snyk".to_string(),
                                                collector: "snyk".to_string(),
                                            },
                                        )
                                        .await
                                    {
                                        collected_guac_errors.push(err.to_string());
                                    }
                                } else {
                                    collected_snyk_errors.push(format!("purl error: {}", original_purl));
                                }

                                for problem in &issue.attributes.problems {
                                    let problem_vuln_input_spec = VulnerabilityInputSpec {
                                        r#type: "snyk".to_string(),
                                        vulnerability_id: problem.id.clone(),
                                    };

                                    ids.push(problem.id.clone());

                                    if let Err(err) = state
                                        .guac_client
                                        .intrinsic()
                                        .ingest_vulnerability(&problem_vuln_input_spec)
                                        .await
                                    {
                                        collected_guac_errors.push(err.to_string());
                                    }

                                    // Create the alias linkage between the root Snyk vuln
                                    // and the problems contained therein.
                                    if let Err(err) = state
                                        .guac_client
                                        .intrinsic()
                                        .ingest_vuln_equal(
                                            &snyk_vuln_input_spec,
                                            &problem_vuln_input_spec,
                                            &VulnEqualInputSpec {
                                                justification: "snyk".to_string(),
                                                origin: "snyk".to_string(),
                                                collector: "snyk".to_string(),
                                            },
                                        )
                                        .await
                                    {
                                        collected_guac_errors.push(err.to_string())
                                    }

                                    // Special-case CVEs
                                    if problem.id.to_lowercase().starts_with("cve") {
                                        let cve_vuln_input_spec = VulnerabilityInputSpec {
                                            r#type: "cve".to_string(),
                                            vulnerability_id: problem.id.clone(),
                                        };

                                        if let Err(err) = state
                                            .guac_client
                                            .intrinsic()
                                            .ingest_vulnerability(&cve_vuln_input_spec)
                                            .await
                                        {
                                            collected_guac_errors.push(err.to_string());
                                        }

                                        if let Err(err) = state
                                            .guac_client
                                            .intrinsic()
                                            .ingest_vuln_equal(
                                                &snyk_vuln_input_spec,
                                                &cve_vuln_input_spec,
                                                &VulnEqualInputSpec {
                                                    justification: "snyk".to_string(),
                                                    origin: "snyk".to_string(),
                                                    collector: "snyk".to_string(),
                                                },
                                            )
                                            .await
                                        {
                                            collected_guac_errors.push(err.to_string())
                                        }
                                    }
                                }

                                for severity in &issue.attributes.severities {
                                    if let (Some(score), Some(vector)) = (&severity.score, &severity.vector) {
                                        if vector.starts_with("CVSS:3.1") {
                                            if let Err(err) = state
                                                .guac_client
                                                .intrinsic()
                                                .ingest_vuln_metadata(
                                                    &snyk_vuln_input_spec,
                                                    &VulnerabilityMetadataInputSpec {
                                                        score_type: VulnerabilityScoreType::CVSSv31,
                                                        score_value: *score as f64,
                                                        timestamp: Default::default(),
                                                        origin: severity.source.clone(),
                                                        collector: "snyk".to_string(),
                                                    },
                                                )
                                                .await
                                            {
                                                collected_guac_errors.push(err.to_string())
                                            }
                                        } else if vector.starts_with("CVSS:3.0") {
                                            if let Err(err) = state
                                                .guac_client
                                                .intrinsic()
                                                .ingest_vuln_metadata(
                                                    &snyk_vuln_input_spec,
                                                    &VulnerabilityMetadataInputSpec {
                                                        score_type: VulnerabilityScoreType::CVSSv3,
                                                        score_value: *score as f64,
                                                        timestamp: Default::default(),
                                                        origin: severity.source.clone(),
                                                        collector: "snyk".to_string(),
                                                    },
                                                )
                                                .await
                                            {
                                                collected_guac_errors.push(err.to_string())
                                            }
                                        }
                                    }
                                }

                                gathered_purls.insert(original_purl.clone(), ids);

                                // finally, expand the Snyk issue into one-or-more v11y Vulnerabilities
                                // which will be ingested in bulk after all of the GUAC machinations.
                                let issue_vulns: Vec<Vulnerability> = issue.clone().into();
                                vulns.extend_from_slice(&issue_vulns)
                            }
                        } else {
                            collected_snyk_errors.push(format!("purl error: {}", purl));
                        }
                    }
                    Err(err) => collected_snyk_errors.push(err.to_string()),
                }
            }
            Err(_) => {
                collected_snyk_errors.push(format!("unable to rewrite {original_purl}"));
            }
        }
    }

    // now stuff all the expanded issue->vulns into v11y proper.
    if !vulns.is_empty() {
        for vuln in &vulns {
            if let Err(err) = state.v11y_client.ingest_vulnerability(vuln).await {
                collected_v11y_errors.push(err.to_string())
            }
        }
    }

    let gathered = CollectPackagesResponse {
        purls: gathered_purls,
        errors: collected_snyk_errors
            .iter()
            .chain(collected_guac_errors.iter())
            .chain(collected_v11y_errors.iter())
            .cloned()
            .collect(),
    };

    Ok(HttpResponse::Ok().json(gathered))
}
