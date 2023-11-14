use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use derive_more::Display;
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
use trustification_infrastructure::endpoint::CollectorOsv;
use trustification_infrastructure::{new_auth, MainContext};

use crate::client::schema::SeverityType;
use crate::{
    client::{schema::Package, QueryBatchRequest, QueryPackageRequest},
    AppState,
};

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "OSV error")]
    Osv,

    #[display(fmt = "Internal error")]
    Internal,
}

impl ResponseError for Error {}

#[derive(OpenApi)]
#[openapi(paths(crate::server::collect_packages,))]
pub struct ApiDoc;

pub async fn run(
    context: MainContext<()>,
    state: Arc<AppState>,
    http: HttpServerConfig<CollectorOsv>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(IpAddr::from_str(&http.bind_addr)?, *http.bind_port);
    let listener = TcpListener::bind(addr)?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    HttpServerBuilder::try_from(http)?
        .authorizer(authorizer)
        .metrics(context.metrics.registry().clone(), "collector_osv")
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

impl From<&CollectPackagesRequest> for QueryBatchRequest {
    fn from(request: &CollectPackagesRequest) -> Self {
        QueryBatchRequest {
            queries: request
                .purls
                .iter()
                .map(|e| QueryPackageRequest {
                    package: Package::Purl { purl: e.clone() },
                })
                .collect(),
        }
    }
}

#[utoipa::path(
    post,
    tag = "collector-osv",
    path = "/api/v1/packages",
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("packages")]
pub async fn collect_packages(
    request: web::Json<CollectPackagesRequest>,
    state: web::Data<AppState>,
) -> actix_web::Result<impl Responder, Error> {
    // OSV allows batch-style querying, convert our collector API into an OSV query.
    let request: QueryBatchRequest = (&*request).into();

    // If we experience an error communicating with OSV, we *do* want to exit
    // early, as any subsequent processes will indeed fail or otherwise be useless.
    let response = state.osv.query_batch(request).await.map_err(|_| Error::Osv)?;

    // we want to make as much progress as possible, so we do not
    // return early using `?` as we want to collect as much as possible
    // while also collecting all relevant errors along the way.
    let mut collected_guac_errors = Vec::new();
    let mut collected_osv_errors = Vec::new();
    let mut collected_v11y_errors = Vec::new();

    for entry in &response.results {
        if let Some(vulns) = &entry.vulns {
            if let Package::Purl { purl } = &entry.package {
                // First, ensure that each purl that came back as part of the OSV
                // response is ingested, which ensures it is known by GUAC and can
                // subsequently be referenced by other verbs.
                if let Err(err) = state
                    .guac_client
                    .intrinsic()
                    .ingest_package(&PackageUrl::from_str(purl).map_err(|_| Error::Internal)?.into())
                    .await
                {
                    log::warn!("guac error {}", err);
                    collected_guac_errors.push(err);
                } else {
                    for vuln in vulns {
                        let mut vulnerability_input_specs = Vec::new();
                        let mut alias_vuln_input_specs = Vec::new();
                        let mut cvss_v3s = Vec::new();
                        // If available ingest a vulnerability using its CVE-ID as the unique key
                        // adopted everywhere in trustification.
                        // To retrieve a vulnerability's CVE-ID, OSV must be called again
                        // in order to retrieve vulnerability's aliases
                        if !vuln.id.to_lowercase().starts_with("cve") {
                            match state.osv.vulns(&vuln.id).await {
                                Ok(Some(osv_vuln)) => {
                                    if let Some(aliases) = &osv_vuln.aliases {
                                        for alias in aliases {
                                            if alias.to_lowercase().starts_with("cve") {
                                                vulnerability_input_specs.push(VulnerabilityInputSpec {
                                                    r#type: "cve".to_string(),
                                                    vulnerability_id: alias.clone(),
                                                });
                                            } else {
                                                alias_vuln_input_specs.push(VulnerabilityInputSpec {
                                                    r#type: "osv".to_string(),
                                                    vulnerability_id: alias.clone(),
                                                })
                                            }
                                        }
                                    }

                                    if let Some(severities) = &osv_vuln.severity {
                                        for severity in severities {
                                            if matches!(severity.severity_type, SeverityType::CVSSv3) {
                                                if let Ok(cvss) = cvss::v3::Base::from_str(&severity.score) {
                                                    cvss_v3s.push(cvss);
                                                }
                                            }
                                        }
                                    }

                                    let v11y_vuln = v11y_client::Vulnerability::from(osv_vuln);
                                    if let Err(err) = state.v11y_client.ingest_vulnerability(&v11y_vuln).await {
                                        log::warn!("v11y error: {err}");
                                        collected_v11y_errors.push(err);
                                    }
                                }
                                Ok(None) => {
                                    // not found, do not add it to the response.
                                }
                                Err(err) => {
                                    log::warn!("OSV vulnerability retrieval for {} failed with {}", vuln.id, err);
                                    collected_osv_errors.push(err);
                                }
                            }
                        }
                        if vulnerability_input_specs.is_empty() {
                            // if no CVE ID alias has been found, then worth adding vulnerability with
                            // the original vuln.id value
                            vulnerability_input_specs.push(VulnerabilityInputSpec {
                                r#type: "osv".to_string(),
                                vulnerability_id: vuln.id.clone(),
                            })
                        } else {
                            // otherwise the original vulnerability must be part of the aliases
                            alias_vuln_input_specs.push(VulnerabilityInputSpec {
                                r#type: "osv".to_string(),
                                vulnerability_id: vuln.id.clone(),
                            })
                        }
                        // Next, for each vulnerability mentioned by OSV, ensure the vulnerability
                        // is known to GUAC so that further verbs can be applied to them.
                        for vulnerability_input_spec in vulnerability_input_specs {
                            if let Err(err) = state
                                .guac_client
                                .intrinsic()
                                .ingest_vulnerability(&vulnerability_input_spec)
                                .await
                            {
                                log::warn!("guac error {}", err);
                                collected_guac_errors.push(err);
                            } else {
                                // Finally, we ensure that GUAC understands the link between the package
                                // and the vulnerabilities related to that package.
                                if let Err(err) = state
                                    .guac_client
                                    .intrinsic()
                                    .ingest_certify_vuln(
                                        &PackageUrl::from_str(purl).map_err(|_| Error::Internal)?.into(),
                                        &vulnerability_input_spec,
                                        &ScanMetadataInput {
                                            db_uri: "https://osv.dev/".to_string(),
                                            db_version: "1.0".to_string(),
                                            scanner_uri: "https://trustification.io/".to_string(),
                                            scanner_version: "1.0".to_string(),
                                            time_scanned: Default::default(),
                                            origin: "osv".to_string(),
                                            collector: "osv".to_string(),
                                        },
                                    )
                                    .await
                                {
                                    log::warn!("guac error {}", err);
                                    collected_guac_errors.push(err);
                                }

                                // ingest each alias found and then correlate it with the "main" vulnerability
                                // ingesting a VulnEqual into guac
                                for alias_vuln_input_spec in &alias_vuln_input_specs {
                                    if let Err(err) = state
                                        .guac_client
                                        .intrinsic()
                                        .ingest_vulnerability(alias_vuln_input_spec)
                                        .await
                                    {
                                        collected_guac_errors.push(err);
                                    } else {
                                        // now both the vulnerability and its alias have been ingested
                                        // so it's time to ingest the VulnEqual
                                        if let Err(err) = state
                                            .guac_client
                                            .intrinsic()
                                            .ingest_vuln_equal(
                                                &vulnerability_input_spec,
                                                alias_vuln_input_spec,
                                                &VulnEqualInputSpec {
                                                    collector: "osv".to_string(),
                                                    origin: "osv".to_string(),
                                                    justification: "osv".to_string(),
                                                },
                                            )
                                            .await
                                        {
                                            collected_guac_errors.push(err);
                                        }
                                    }
                                }

                                for cvss_v3 in &cvss_v3s {
                                    if let Err(err) = state
                                        .guac_client
                                        .intrinsic()
                                        .ingest_vuln_metadata(
                                            &vulnerability_input_spec,
                                            &VulnerabilityMetadataInputSpec {
                                                score_type: if cvss_v3.minor_version == 0 {
                                                    VulnerabilityScoreType::CVSSv3
                                                } else {
                                                    VulnerabilityScoreType::CVSSv31
                                                },
                                                score_value: cvss_v3.score().value(),
                                                timestamp: Default::default(),
                                                origin: "osv".to_string(),
                                                collector: "osv".to_string(),
                                            },
                                        )
                                        .await
                                    {
                                        collected_guac_errors.push(err)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut gathered = CollectPackagesResponse::from(response);

    gathered.errors.extend(
        collected_osv_errors
            .iter()
            .map(|err| err.to_string())
            .chain(collected_v11y_errors.iter().map(|err| err.to_string()))
            .chain(collected_guac_errors.iter().map(|err| err.to_string())),
    );

    Ok(HttpResponse::Ok().json(gathered))
}
