use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use guac::client::intrinsic::certify_vuln::CertifyVulnSpec;
use packageurl::PackageUrl;
use serde_json::value::RawValue;
use utoipa::OpenApi;

use exhort_model::*;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc};
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::Exhort;
use trustification_infrastructure::MainContext;

use crate::AppState;

#[derive(OpenApi)]
#[openapi(
    servers(
        (url = "/api/v1")
    ),
    tags(
        (name = "exhort")
    ),
    paths(
        analyze,
    ),
    components(
        schemas(
            AnalyzeRequest,
            AnalyzeResponse,
            v11y_client::Vulnerability,
            v11y_client::Affected,
            v11y_client::Reference,
            v11y_client::Severity,
            v11y_client::Range,
            v11y_client::ScoreType,
            v11y_client::Version,
        )
    )
)]
pub struct ApiDoc;

pub async fn run(
    state: Arc<AppState>,
    http: HttpServerConfig<Exhort>,
    context: MainContext<()>,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    swagger_oidc: Option<Arc<SwaggerUiOidc>>,
) -> Result<(), anyhow::Error> {
    let state = web::Data::from(state);

    let http = HttpServerBuilder::try_from(http)?
        .metrics(context.metrics.registry().clone(), "exhort")
        .authorizer(authorizer.clone())
        .configure(move |svc| {
            let authenticator = authenticator.clone();
            let swagger_oidc = swagger_oidc.clone();

            svc.app_data(state.clone())
                .configure(|cfg| config(cfg, authenticator, swagger_oidc));
        });

    http.run().await
}

pub fn config(
    cfg: &mut web::ServiceConfig,
    _auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) {
    cfg.service(
        web::scope("/api/v1")
            //.wrap(new_auth!(auth))
            .service(analyze),
    )
    .service(swagger_ui_with_auth(ApiDoc::openapi(), swagger_ui_oidc));
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("http error: {0}")]
    Http(reqwest::Error),
    #[error("collectorist error: {errors:?}")]
    Collectorist { errors: Vec<String> },
}

impl ResponseError for Error {}

impl From<reqwest::Error> for Error {
    fn from(inner: reqwest::Error) -> Self {
        Self::Http(inner)
    }
}

impl From<collectorist_client::Error> for Error {
    fn from(inner: collectorist_client::Error) -> Self {
        Self::Collectorist {
            errors: vec![inner.to_string()],
        }
    }
}

#[utoipa::path(
    post,
    request_body = AnalyzeRequest,
    responses(
        (status = 200, body = AnalyzeResponse, description = "Analyzed pURLs"),
    ),
)]
#[post("analyze")]
async fn analyze(state: web::Data<AppState>, request: web::Json<AnalyzeRequest>) -> actix_web::Result<impl Responder> {
    // If the collectorist client provides a hard error, go ahead and return it
    let collectorist_response = state
        .collectorist_client
        .collect_packages(request.purls.clone())
        .await
        .map_err(Error::from)?;

    let mut response = AnalyzeResponse::new();

    // Else... collect any soft-errors, and continue doing out best.
    response.errors = collectorist_response.errors.clone();

    let mut vuln_ids = HashSet::new();

    for purl_str in &request.purls {
        // Ask GUAC about each purl in the original request.
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            match state
                .guac_client
                .intrinsic()
                .certify_vuln(&CertifyVulnSpec {
                    package: Some(purl.into()),
                    ..Default::default()
                })
                .await
            {
                Ok(vulns) => {
                    // Add mappings from purl->vuln for all discovered
                    for vuln in vulns {
                        for vuln_id in vuln.vulnerability.vulnerability_ids {
                            if vuln_id.vulnerability_id.starts_with("cve") {
                                response.add_package_vulnerability(purl_str, &vuln_id.vulnerability_id);
                                vuln_ids.insert(vuln_id.vulnerability_id);
                            }
                        }
                    }
                }
                Err(err) => {
                    // if a soft error has occurred, record it and keep trucking.
                    log::error!("guac error {}", err);
                    response.errors.push(err.to_string());
                }
            }
        }
    }

    // For every vulnerability that appears within any of the purl->vuln
    // mappings, go collect the vulnerability details from v11y, doing
    // our best effort and not allowing soft errors to fail the process.
    for vuln_id in vuln_ids {
        match state.v11y_client.get_cve(&vuln_id).await {
            Ok(vulnerabilities) => {
                if vulnerabilities.status() == 200 {
                    let cve: Result<Box<RawValue>, _> = vulnerabilities.json().await;
                    match cve {
                        Ok(cve) => {
                            //response.vulnerabilities.extend(vulns.iter().cloned() );
                            response.vulnerabilities.push(cve);
                        }
                        Err(err) => {
                            log::error!("v11y cve error {} {}", err, vuln_id);
                            response.errors.push(err.to_string());
                        }
                    }
                } else {
                    log::error!("v11y can't find {}", vuln_id);
                    response
                        .errors
                        .push(format!("v11y error: unable to locate {}", vuln_id));
                }
            }
            Err(err) => {
                log::error!("v11y error {}", err);
                response.errors.push(err.to_string())
            }
        }
    }
    Ok(HttpResponse::Ok().json(response))
}
