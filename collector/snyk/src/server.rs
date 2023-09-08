use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::Ordering;
use std::time::Duration;
use actix_web::{App, HttpResponse, HttpServer, post, Responder, ResponseError, web};
use actix_web::middleware::{Compress, Logger};
use log::{info, warn};
use reqwest::Url;
use tokio::time::sleep;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use collector_client::{CollectPackagesRequest, CollectVulnerabilitiesRequest};
use collectorist_client::{CollectorConfig, Interest};
use v11y_client::Vulnerability;
use crate::client::{Error, SnykClient};
use crate::SharedState;

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

impl ResponseError for Error {

}

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(bind.into())?;
    let addr = listener.local_addr()?;
    log::info!("listening on {}", addr);

    state.addr.write().await.replace(addr);

    HttpServer::new(move || App::new().app_data(web::Data::new(state.clone())).configure(config))
        .listen(listener)?
        .run()
        .await?;
    Ok(())
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
    state: web::Data<SharedState>,
) -> actix_web::Result<impl Responder> {

    let client = SnykClient::new(
        &state.snyk_org_id,
        &state.snyk_token,
    );

    let mut vulns: Vec<v11y_client::Vulnerability> = Vec::new();

    for purl in &request.purls {
        println!("snyk query {}", purl);
        for issue in client.issues(purl).await? {
            println!("snyk issue {:#?}", issue);
            let issue_vulns: Vec<Vulnerability> = issue.into();
            println!("v11y vulns {}", issue_vulns.len());
            vulns.extend_from_slice(
                &issue_vulns
            )
        }
    }

    for vuln in vulns {
        println!("{:#?}", vuln);
    }

    Ok(HttpResponse::Ok().finish())
}


pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
            .service(collect_packages)
    )
        .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

pub async fn register_with_collectorist(state: SharedState) {
    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = Url::parse(&format!("http://{}:{}/api/v1/", addr.ip(), addr.port())).unwrap();
                info!(
                    "registering with collectorist at {} with callback={}",
                    state.collectorist_client.register_collector_url(),
                    url
                );
                match state
                    .collectorist_client
                    .register_collector(CollectorConfig {
                        url,
                        cadence: Default::default(),
                        interests: vec![Interest::Package],
                    })
                    .await
                {
                    Ok(response) => {
                        state.guac_url.write().await.replace(response.guac_url);
                        state.connected.store(true, Ordering::Relaxed);
                        info!("successfully registered with collectorist")
                    }
                    Err(e) => {
                        warn!("failed to register with collectorist: {}", e)
                    }
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn deregister_with_collectorist(state: SharedState) {
    if state.collectorist_client.deregister_collector().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }

    state.connected.store(false, Ordering::Relaxed);
    state.guac_url.write().await.take();
}
