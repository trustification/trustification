use crate::app_state::AppState;
use crate::error::Error;
use crate::search::QueryParams;
use crate::service::v11y::V11yService;
use actix_web::web::ServiceConfig;
use actix_web::{web, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use cvss::v3::Score;
use futures::future::try_join3;
use spog_model::prelude::*;
use std::fmt::Write;
use std::sync::Arc;
use tracing::instrument;
use trustification_api::search::SearchOptions;
use trustification_auth::authenticator::Authenticator;
use trustification_auth::client::TokenProvider;
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
    state: web::Data<AppState>,
    query: web::Query<SearchQuery>,
    access_token: Option<BearerAuth>,
) -> Result<impl Responder, Error> {
    let (cve, advisories, sboms) = try_join3(
        async { create_cve_suggestions(&v11y, &query.term).await },
        async { create_advisory_suggestions(&state, &query.term, &access_token).await },
        async { create_sbom_suggestions(&state, &query.term, &access_token).await },
    )
    .await?;

    // collect all

    let mut result = cve;

    for advisory in advisories {
        if let Action::Advisory(advisory_id) = &advisory.action {
            if let Some(cve_is_advisory) = result.iter_mut().find_map(|cve| match &mut cve.action {
                Action::Cve { id, advisory } if id == advisory_id => Some(advisory),
                _ => None,
            }) {
                *cve_is_advisory = true;
                // next item, don't add
                break;
            }
        }

        result.push(advisory);
    }

    result.extend(sboms);

    // done

    Ok(web::Json(result))
}

#[instrument(skip(state, token_provider), ret, err)]
async fn create_sbom_suggestions(
    state: &AppState,
    term: &str,
    token_provider: &dyn TokenProvider,
) -> Result<Vec<Suggestion>, Error> {
    let term = term.replace('\"', "");
    let q = format!(r#""{term}" in:package sort:created"#);

    let result = state
        .search_sbom(&q, 0, 3, SearchOptions::default(), token_provider)
        .await?;

    Ok(result
        .result
        .into_iter()
        .map(|hit| {
            let description = format!("{} ({})", hit.document.version, hit.document.supplier);

            Suggestion {
                label: hit.document.name,
                description: Some(description),
                action: Action::Sbom(hit.document.id),
            }
        })
        .collect())
}

#[instrument(skip(state, token_provider), ret, err)]
async fn create_advisory_suggestions(
    state: &AppState,
    term: &str,
    token_provider: &dyn TokenProvider,
) -> Result<Vec<Suggestion>, Error> {
    let term = term.replace('\"', "");
    let q = format!(r#""{term}""#);

    let result = state
        .search_vex(&q, 0, 3, SearchOptions::default(), token_provider)
        .await?;

    Ok(result
        .result
        .into_iter()
        .map(|hit| {
            let description = hit.document.advisory_title;

            Suggestion {
                label: hit.document.advisory_id.clone(),
                description: Some(description),
                action: Action::Advisory(hit.document.advisory_id),
            }
        })
        .collect())
}

#[instrument(skip(v11y), ret, err)]
async fn create_cve_suggestions(v11y: &V11yService, term: &str) -> Result<Vec<Suggestion>, Error> {
    let term = term.replace('\"', "");
    let q = format!(r#""{term}" is:published"#);

    let result = v11y.search(QueryParams { q, offset: 0, limit: 3 }).await?;

    Ok(result
        .result
        .into_iter()
        .map(|hit| {
            let mut description = hit.document.title.unwrap_or_default();

            // no title? try description next.
            if description.is_empty() {
                if let Some(desc) = hit.document.descriptions.first() {
                    description = desc.chars().take(60).collect();
                    if desc.len() > 60 {
                        description.push('…');
                    }
                }
            }

            // add score
            if let Some(score) = hit.document.cvss3x_score {
                if !description.is_empty() {
                    description.push_str(" · ");
                }
                let severity = Score::from(score).severity();
                let _ = write!(&mut description, "CVSS: {score:.1} ({severity})");
            }

            Suggestion {
                label: hit.document.id.clone(),
                description: if description.is_empty() {
                    None
                } else {
                    Some(description)
                },
                action: Action::Cve {
                    id: hit.document.id,
                    advisory: false,
                },
            }
        })
        .collect())
}
