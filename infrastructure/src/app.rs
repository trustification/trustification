use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    middleware::Logger,
    App, Error,
};
use actix_web_extras::middleware::Condition;
use actix_web_httpauth::middleware::HttpAuthentication;
use actix_web_prom::PrometheusMetrics;
use std::sync::Arc;
use trustification_auth::actix::openid_validator;
use trustification_auth::Authenticator;

#[derive(Default)]
pub struct AppOptions {
    pub cors: Option<Cors>,
    pub metrics: Option<PrometheusMetrics>,
    pub authenticator: Option<Arc<Authenticator>>,
}

pub fn new_app(
    options: AppOptions,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = Error,
        InitError = (),
    >,
> {
    App::new()
        .wrap(Condition::from_option(options.authenticator.map(
            move |authenticator| {
                HttpAuthentication::bearer(move |req, auth| openid_validator(req, auth, authenticator.clone()))
            },
        )))
        .wrap(Condition::from_option(options.cors))
        .wrap(Condition::from_option(options.metrics))
        .wrap(Logger::default())
}
