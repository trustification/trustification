mod ws;

use std::collections::HashMap;

use actix_cors::Cors;
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use tokio::task::spawn_local;

use crate::workload::{by_ns, WorkloadState};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: String,
}

#[get("/api/v1/workload")]
async fn get_workload(map: web::Data<WorkloadState>) -> impl Responder {
    HttpResponse::Ok().json(map.get_state().await.into_iter().collect::<HashMap<_, _>>())
}

#[get("/api/v1/workload_stream")]
pub async fn workload_stream(
    req: HttpRequest,
    stream: web::Payload,
    map: web::Data<WorkloadState>,
) -> Result<HttpResponse, actix_web::Error> {
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;
    let subscription = map.subscribe(32).await;
    spawn_local(ws::run(subscription, session, msg_stream));
    Ok(res)
}

#[get("/api/v1/workload_stream/{namespace}")]
pub async fn workload_stream_ns(
    req: HttpRequest,
    stream: web::Payload,
    map: web::Data<WorkloadState>,
    path: web::Path<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let (workload, runner) = by_ns(&map, path.into_inner()).await;
    let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;
    let subscription = workload.subscribe(32).await;

    // run either of them to completion
    spawn_local(async {
        tokio::select! {
            _ = ws::run(subscription, session, msg_stream) => {},
            _ = runner => {},
        }
    });

    Ok(res)
}

/*
#[get("/v1/images/{namespace}")]
async fn get_containers_ns(path: web::Path<String>, store: web::Data<Store>) -> impl Responder {
    let ns = path.into_inner();
    HttpResponse::Ok().json(store.get_containers_ns(&ns).await)
}*/

pub async fn run(config: ServerConfig, map: WorkloadState) -> anyhow::Result<()> {
    let map = web::Data::new(map);

    HttpServer::new(move || {
        let cors = Cors::default()
            .send_wildcard()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(map.clone())
            .wrap(cors)
            .service(get_workload)
            .service(workload_stream)
            .service(workload_stream_ns)
        //.service(get_containers_ns)
    })
    .bind(&config.bind_addr)?
    .run()
    .await?;

    Ok(())
}
