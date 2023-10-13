use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use derive_more::{Display, Error, From};
use exhort_model::*;
use guac::client::intrinsic::certify_vuln::CertifyVulnSpec;
use packageurl::PackageUrl;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc};
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::Exhort;
use trustification_infrastructure::MainContext;
use utoipa::OpenApi;

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

#[derive(Debug, Display, Error, From)]
enum Error {
    Collectorist,
    Guac,
    V11y,
}

impl ResponseError for Error {}

#[utoipa::path(
    post,
    request_body = AnalyzeRequest,
    responses(
        (status = 200, body = AnalyzeResponse, description = "Analyzed pURLs"),
    ),
)]
#[post("analyze")]
async fn analyze(state: web::Data<AppState>, request: web::Json<AnalyzeRequest>) -> actix_web::Result<impl Responder> {
    state
        .collectorist_client
        .collect_packages(request.purls.clone())
        .await
        .map_err(|e| {
            log::error!("collectorist error {}", e);
            Error::Collectorist
        })?;

    let mut response = AnalyzeResponse::new();

    let mut vuln_ids = HashSet::new();

    for purl_str in &request.purls {
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            for vuln in state
                .guac_client
                .intrinsic()
                .certify_vuln(&CertifyVulnSpec {
                    package: Some(purl.into()),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    log::error!("GUAC error {}", e);
                    Error::Guac
                })?
            {
                for vuln_id in vuln.vulnerability.vulnerability_ids {
                    response.add_package_vulnerability(purl_str, &vuln_id.vulnerability_id);
                    vuln_ids.insert(vuln_id.vulnerability_id);
                }
            }
        }
    }

    for vuln_id in vuln_ids {
        for vuln in state.v11y_client.get_vulnerability(&vuln_id).await.map_err(|e| {
            log::error!("v11y error {}", e);
            Error::V11y
        })? {
            response.add_vulnerability(&vuln);
        }
    }
    Ok(HttpResponse::Ok().json(response))
}
