use crate::error::Error;
use crate::search::QueryParams;
use crate::service::v11y::V11yService;
use actix_web::web::ServiceConfig;
use actix_web::{web, Responder};
use cvss::v3::Score;
use spog_model::prelude::*;
use std::fmt::Write;
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(
            web::resource("/api/v1/suggestions/search")
                .wrap(new_auth!(auth))
                .to(search_suggestions),
        );
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SearchQuery {
    #[serde(default)]
    term: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/suggestions/search",
        responses(
            (status = OK, description = "The resulting suggestions", body = Vec<Suggestion>),
        ),
    params(
        ("term" = String, Query, description = "The search term to provide suggestions for")
    )
)]
async fn search_suggestions(
    v11y: web::Data<V11yService>,
    query: web::Query<SearchQuery>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(create_suggestions(&v11y, &query.term).await?))
}

async fn create_suggestions(v11y: &V11yService, term: &str) -> Result<Vec<Suggestion>, Error> {
    let term = term.replace("\"", "");
    let q = format!(r#""{term}" is:published"#);

    let result = v11y.search(QueryParams { q, offset: 0, limit: 3 }).await?;

    Ok(result
        .result
        .into_iter()
        .map(|doc| {
            let mut description = doc.document.title.unwrap_or_default();

            // no title? try description next.
            if description.is_empty() {
                if let Some(desc) = doc.document.descriptions.get(0) {
                    description = desc.chars().take(60).collect();
                    if desc.len() > 60 {
                        description.push_str("…");
                    }
                }
            }

            // add score
            if let Some(score) = doc.document.cvss3x_score {
                if !description.is_empty() {
                    description.push_str(" · ");
                }
                let severity = Score::from(score).severity();
                let _ = write!(&mut description, "CVSS: {score:.1} ({severity})");
            }

            Suggestion {
                label: doc.document.id.clone(),
                description: if description.is_empty() {
                    None
                } else {
                    Some(description)
                },
                action: Action::Cve(doc.document.id),
            }
        })
        .collect())
}
