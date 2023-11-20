use std::collections::HashMap;

use actix_web::{post, web, HttpResponse, Responder};
use collector_client::CollectPackagesResponse;

use collectorist_client::CollectPackagesRequest;

use crate::state::AppState;

/// Post a list of purls to be "gathered"
#[utoipa::path(
    post,
    tag = "collectorist",
    path = "/api/v1/packages",
    responses(
        (status = 200, description = "Purls gathered"),
        (status = BAD_REQUEST, description = "Malformed input"),
    ),
)]
#[post("/packages")]
pub(crate) async fn collect_packages(
    state: web::Data<AppState>,
    input: web::Json<CollectPackagesRequest>,
) -> actix_web::Result<impl Responder> {
    let purls = input.into_inner();

    // Fan out the collect-packages request to all collectors.
    let results = state.coordinator.collect_packages(&state, purls).await;

    let mut purls = HashMap::<String, Vec<String>>::new();
    let mut errors = Vec::new();

    // Merge the results into a total aggregate.

    for collected in results {
        for k in collected.purls.keys() {
            // If there are already vulnerabilities recorded for a given
            // package, we need to extend the existing list. If not,
            // we initialize the list with the first bolus of results.
            if let Some(vulns) = purls.get_mut(k) {
                vulns.extend(collected.purls[k].iter().cloned());
            } else {
                purls.insert(k.clone(), collected.purls[k].clone());
            }
        }
        // Aggregate all errors that might've come up from the collector.
        errors.extend_from_slice(&collected.errors);
    }

    let result = CollectPackagesResponse { purls, errors };
    Ok(HttpResponse::Ok().json(&result))
}
