use crate::{IndexerCommand, IndexerStatus};
use actix_web::{get, post, web, web::ServiceConfig, HttpResponse};
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Mutex};

#[post("/reindex")]
async fn post_command(sender: web::Data<Sender<IndexerCommand>>) -> HttpResponse {
    if let Err(e) = sender.send(IndexerCommand::Reindex).await {
        HttpResponse::InternalServerError().body(e.to_string())
    } else {
        HttpResponse::Ok().finish()
    }
}

#[get("/reindex")]
async fn get_status(status: web::Data<Arc<Mutex<IndexerStatus>>>) -> HttpResponse {
    let status = status.lock().await.clone();
    let status = match status {
        IndexerStatus::Running => "running".to_string(),
        IndexerStatus::Reindexing { progress } => {
            format!("reindexing ({} objects)", progress)
        }
        IndexerStatus::Failed { error } => {
            format!("indexer failed: {:?}", error)
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "status": status,
    }))
}

pub fn configure(status: Arc<Mutex<IndexerStatus>>, sender: Sender<IndexerCommand>, config: &mut ServiceConfig) {
    config
        .app_data(web::Data::new(sender))
        .app_data(web::Data::new(status))
        .service(post_command)
        .service(get_status);
}
