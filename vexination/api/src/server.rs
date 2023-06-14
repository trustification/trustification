use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{
    http::header::{self, ContentType},
    middleware::{Compress, Logger},
    web::{self, Bytes},
    App, HttpResponse, HttpServer, Responder,
};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use trustification_storage::Storage;
use vexination_model::prelude::*;

use crate::SharedState;

pub async fn run<B: Into<SocketAddr>>(state: SharedState, bind: B) -> Result<(), anyhow::Error> {
    let addr = bind.into();
    tracing::debug!("listening on {}", addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Compress::default())
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .app_data(web::Data::new(state.clone()))
            .service(
                web::scope("/api/v1")
                    .route("/vex", web::get().to(query_vex))
                    .route("/vex", web::post().to(publish_vex))
                    .route("/vex/search", web::get().to(search_vex)),
            )
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

async fn fetch_object(storage: &Storage, key: &str) -> HttpResponse {
    match storage.get_decoded_stream(key).await {
        Ok(stream) => HttpResponse::Ok().content_type(ContentType::json()).streaming(stream),
        Err(e) => {
            tracing::warn!("Unable to locate object with key {}: {:?}", key, e);
            HttpResponse::NotFound().finish()
        }
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    advisory: String,
}

async fn query_vex(state: web::Data<SharedState>, params: web::Query<QueryParams>) -> HttpResponse {
    let storage = state.storage.read().await;
    fetch_object(&storage, &params.advisory).await
}

#[derive(Debug, Deserialize)]
struct PublishParams {
    advisory: Option<String>,
}

async fn publish_vex(state: web::Data<SharedState>, params: web::Query<PublishParams>, data: Bytes) -> HttpResponse {
    let params = params.into_inner();
    let advisory = if let Some(advisory) = params.advisory {
        advisory.to_string()
    } else {
        match serde_json::from_slice::<csaf::Csaf>(&data) {
            Ok(data) => data.document.tracking.id,
            Err(e) => {
                tracing::warn!("Unknown input format: {:?}", e);
                return HttpResponse::BadRequest().into();
            }
        }
    };

    let storage = state.storage.write().await;
    tracing::debug!("Storing new VEX with id: {advisory}");
    match storage.put_slice(&advisory, &data).await {
        Ok(_) => {
            let msg = format!("VEX of size {} stored successfully", &data[..].len());
            tracing::trace!(msg);
            HttpResponse::Created().body(msg)
        }
        Err(e) => {
            let msg = format!("Error storing VEX: {:?}", e);
            tracing::warn!(msg);
            HttpResponse::InternalServerError().body(msg)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
    #[serde(default = "default_offset")]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_offset() -> usize {
    0
}

const fn default_limit() -> usize {
    10
}

async fn search_vex(state: web::Data<SharedState>, params: web::Query<SearchParams>) -> impl Responder {
    let params = params.into_inner();

    tracing::info!("Querying VEX using {}", params.q);

    let index = state.index.read().await;
    let result = index.search(&params.q, params.offset, params.limit);

    let result = match result {
        Err(e) => {
            tracing::info!("Error searching: {:?}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
        Ok(result) => result,
    };

    HttpResponse::Ok().json(SearchResult {
        total: result.1,
        result: result.0,
    })
}
