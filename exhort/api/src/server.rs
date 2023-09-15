use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{
    middleware::{Compress, Logger},
    post, web, HttpResponse, HttpServer, Responder, ResponseError,
};
use derive_more::{Display, Error, From};
use guac::client::intrinsic::certify_vuln::CertifyVulnSpec;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use utoipa::OpenApi;

use trustification_auth::authenticator::Authenticator;
use trustification_auth::authorizer::Authorizer;
use trustification_auth::swagger_ui::{swagger_ui_with_auth, SwaggerUiOidc};
use trustification_infrastructure::app::{new_app, AppOptions};
//use trustification_infrastructure::new_auth;
use v11y_client::Vulnerability;

use crate::{AppState, SharedState};

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
    )
)]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(
    state: SharedState,
    bind: B,
    authenticator: Option<Arc<Authenticator>>,
    authorizer: Authorizer,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(bind.into())?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    let state = web::Data::from(state);

    HttpServer::new(move || {
        let cors = Cors::permissive();
        let authenticator = authenticator.clone();
        let authorizer = authorizer.clone();
        let swagger_ui_oidc = swagger_ui_oidc.clone();
        new_app(AppOptions {
            cors: Some(cors),
            metrics: None,
            authenticator: None,
            authorizer,
        })
        .app_data(state.clone())
        .configure(|cfg| config(cfg, authenticator, swagger_ui_oidc))
    })
    .listen(listener)?
    .run()
    .await?;
    Ok(())
}

pub fn config(
    cfg: &mut web::ServiceConfig,
    _auth: Option<Arc<Authenticator>>,
    swagger_ui_oidc: Option<Arc<SwaggerUiOidc>>,
) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
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
    responses(
        (status = 200, description = "Analyzed pURLs"),
    ),
)]
#[post("analyze")]
async fn analyze(state: web::Data<AppState>, request: web::Json<AnalyzeRequest>) -> actix_web::Result<impl Responder> {
    println!("analyze A");
    state
        .collectorist_client
        .collect_packages(request.purls.clone())
        .await
        .map_err(|e| {
            println!("COLLECTORIST {}", e);
            log::error!("collectorist error {}", e);
            Error::Collectorist
        })?;

    println!("analyze B");
    let mut response = AnalyzeResponse::new();

    let mut vuln_ids = HashSet::new();

    println!("analyze C");
    for purl_str in &request.purls {
        println!("analyze D {}", purl_str);
        if let Ok(purl) = PackageUrl::from_str(purl_str) {
            println!("analyze E");
            for vuln in state
                .guac_client
                .intrinsic()
                .certify_vuln(&CertifyVulnSpec {
                    package: Some(purl.into()),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    println!("GUAC {}", e);
                    log::error!("GUAC error {}", e);
                    Error::Guac
                })?
            {
                println!("analyze F");
                for vuln_id in vuln.vulnerability.vulnerability_ids {
                    println!("analyze G");
                    response.add_package_vulnerability(purl_str, &vuln_id.vulnerability_id);
                    vuln_ids.insert(vuln_id.vulnerability_id);
                }
            }
        }
    }

    println!("analyze H");
    for vuln_id in vuln_ids {
        println!("analyze I");
        for vuln in state.v11y_client.get_vulnerability(&vuln_id).await.map_err(|e| {
            println!("v11y {}", e);
            log::error!("v11y error {}", e);
            Error::V11y
        })? {
            println!("analyze J");
            response.add_vulnerability(&vuln);
        }
    }
    println!("analyze K");
    Ok(HttpResponse::Ok().json(response))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalyzeRequest {
    pub purls: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalyzeResponse {
    pub packages: HashMap<String, Vec<String>>,
    pub vulnerabilities: HashMap<String, Vec<Vulnerability>>,
}

impl AnalyzeResponse {
    pub fn new() -> Self {
        Self {
            packages: Default::default(),
            vulnerabilities: Default::default(),
        }
    }

    pub fn add_package_vulnerability(&mut self, purl: &str, vuln_id: &str) {
        if !self.packages.contains_key(purl) {
            self.packages.insert(purl.to_string(), Vec::new());
        }

        if let Some(inner) = self.packages.get_mut(purl) {
            inner.push(vuln_id.to_string());
        }
    }

    pub fn add_vulnerability(&mut self, vuln: &Vulnerability) {
        if !self.vulnerabilities.contains_key(&vuln.id) {
            self.vulnerabilities.insert(vuln.id.clone(), Vec::new());
        }

        if let Some(inner) = self.vulnerabilities.get_mut(&vuln.id) {
            inner.push(vuln.clone())
        }
    }
}
