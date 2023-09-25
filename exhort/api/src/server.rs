use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use actix_web::{post, web, HttpResponse, Responder, ResponseError};
use derive_more::{Display, Error, From};
use guac::client::intrinsic::certify_vuln::CertifyVulnSpec;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc};
use trustification_infrastructure::app::http::{HttpServerBuilder, HttpServerConfig};
use trustification_infrastructure::endpoint::Exhort;
use trustification_infrastructure::MainContext;
use utoipa::openapi::schema::AdditionalProperties;
use utoipa::openapi::{ArrayBuilder, Object, ObjectBuilder, RefOr, SchemaType};
use utoipa::{OpenApi, ToSchema};
//use trustification_infrastructure::new_auth;
use v11y_client::Vulnerability;

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

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AnalyzeRequest {
    pub purls: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AnalyzeResponse {
    #[schema(schema_with = response_affected)]
    pub affected: HashMap<String, Vec<String>>,
    //#[schema(additional_properties, value_type = Vulnerability)]
    pub vulnerabilities: Vec<Vulnerability>,
}

fn response_affected() -> Object {
    ObjectBuilder::new()
        .schema_type(SchemaType::Object)
        .additional_properties(Some(AdditionalProperties::RefOr(RefOr::T(
            ArrayBuilder::new()
                .items(
                    ObjectBuilder::new()
                        .schema_type(SchemaType::String)
                        .description(Some("vulnerability ID"))
                        .build(),
                )
                .build()
                .into(),
        ))))
        .build()
}

impl AnalyzeResponse {
    pub fn new() -> Self {
        Self {
            affected: Default::default(),
            vulnerabilities: Default::default(),
        }
    }

    pub fn add_package_vulnerability(&mut self, purl: &str, vuln_id: &str) {
        if !self.affected.contains_key(purl) {
            self.affected.insert(purl.to_string(), Vec::new());
        }

        if let Some(inner) = self.affected.get_mut(purl) {
            inner.push(vuln_id.to_string());
        }
    }

    pub fn add_vulnerability(&mut self, vuln: &Vulnerability) {
        self.vulnerabilities.push(vuln.clone());
        //if !self.vulnerabilities.contains_key(&vuln.id) {
        //self.vulnerabilities.insert(vuln.id.clone(), Vec::new());
        //}

        //if let Some(inner) = self.vulnerabilities.get_mut(&vuln.id) {
        //inner.push(vuln.clone())
        //}
    }
}
