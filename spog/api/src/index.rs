use actix_web::{get, http::uri::Builder, web::ServiceConfig, HttpRequest, HttpResponse};

pub(crate) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(index);
    }
}

const ENDPOINTS: &[&str] = &[
    "/.well-known/trustification/version",
    "/api/package",
    "/api/vulnerability",
    "/swagger-ui/",
    "/openapi.json",
];

#[utoipa::path(
    responses(
        (status = 200, description = "API", body = Vec<String>),
    )
)]
#[get("/")]
pub async fn index(req: HttpRequest) -> HttpResponse {
    let mut apis = Vec::new();
    let conn = req.connection_info();

    for api in ENDPOINTS {
        if let Ok(uri) = Builder::new()
            .authority(conn.host())
            .scheme(conn.scheme())
            .path_and_query(*api)
            .build()
        {
            apis.push(uri.to_string());
        }
    }
    HttpResponse::Ok().json(apis)
}
