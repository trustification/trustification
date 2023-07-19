use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::Ordering;
use std::time::Duration;

use actix_web::middleware::{Compress, Logger};
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use log::{info, warn};
use tokio::time::sleep;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use collector_client::{GatherRequest, GatherResponse};
use collectorist_client::CollectorConfig;

use crate::client::schema::Package;
use crate::client::{OsvClient, QueryBatchRequest, QueryPackageRequest};
use crate::SharedState;

#[derive(OpenApi)]
#[openapi(paths(crate::server::gather))]
pub struct ApiDoc;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(bind.into())?;
    let addr = listener.local_addr()?;
    log::debug!("listening on {}", addr);

    state.addr.write().await.replace(addr);

    HttpServer::new(move || App::new().app_data(web::Data::new(state.clone())).configure(config))
        .listen(listener)?
        .run()
        .await?;
    Ok(())
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .wrap(Logger::default())
            .wrap(Compress::default())
            .service(gather),
    )
    .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", ApiDoc::openapi()));
}

impl From<&GatherRequest> for QueryBatchRequest {
    fn from(request: &GatherRequest) -> Self {
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
    path = "/api/v1/gather",
    responses(
        (status = 200, description = "Requested pURLs gathered"),
    ),
)]
#[post("gather")]
pub async fn gather(request: web::Json<GatherRequest>) -> impl Responder {
    let request: QueryBatchRequest = (&*request).into();

    if let Ok(response) = OsvClient::query_batch(request).await {
        let purls: Vec<_> = response
            .results
            .iter()
            .flat_map(|e| {
                if let Package::Purl { purl } = &e.package {
                    Some(purl)
                } else {
                    None
                }
            })
            .cloned()
            .collect();

        let response = GatherResponse { purls };

        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

pub async fn register_with_collectorist(state: SharedState) {
    loop {
        if let Some(addr) = *state.addr.read().await {
            if !state.connected.load(Ordering::Relaxed) {
                let url = format!("http://{}:{}/api/v1/gather", addr.ip(), addr.port());
                info!("registering with collectorist: callback={}", url);
                if state
                    .client
                    .register(CollectorConfig {
                        url,
                        cadence: Default::default(),
                    })
                    .await
                    .is_ok()
                {
                    state.connected.store(true, Ordering::Relaxed);
                    info!("successfully registered with collectorist")
                } else {
                    warn!("failed to register with collectorist")
                }
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn deregister_with_collectorist(state: SharedState) {
    if state.client.deregister().await.is_ok() {
        info!("deregistered with collectorist");
    } else {
        warn!("failed to deregister with collectorist");
    }
}
