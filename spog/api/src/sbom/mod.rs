mod get;
mod search;
mod vuln;

pub use get::*;
pub use search::*;
pub use vuln::*;

use actix_web::{web, web::ServiceConfig};
use std::sync::Arc;
use trustification_auth::authenticator::Authenticator;
use trustification_infrastructure::new_auth;

pub(crate) fn configure(auth: Option<Arc<Authenticator>>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(web::resource("/api/v1/sbom/search").wrap(new_auth!(auth)).to(search));
        // the get operation doesn't get the authenticator added, as we check this using the access_token query parameter
        config.service(web::resource("/api/v1/sbom").to(get));
        config.service(web::resource("/api/v1/sbom/vulnerabilities").to(get_vulnerabilities));
    }
}
