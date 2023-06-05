use std::sync::Arc;

use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{web, App, HttpResponse, HttpServer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::sbom::SbomRegistry;
use crate::{guac, index, package, search, vulnerability, Run};

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

pub struct Server {
    run: Run,
}

#[derive(OpenApi)]
#[openapi(
        paths(
            package::get_package,
            package::get_packages,
            package::search_packages,
            package::search_package_dependencies,
            package::search_package_dependents,
            vulnerability::get_vulnerability,
        ),
        components(
            schemas(package::Package, package::PackageList, package::PackageDependencies, package::PackageDependents, package::PackageRef, package::SnykData, package::VulnerabilityRef, vulnerability::Vulnerability)
        ),
        tags(
            (name = "package", description = "Package query endpoints."),
            (name = "vulnerability", description = "Vulnerability query endpoints")
        ),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(run: Run) -> Self {
        Self { run }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let openapi = ApiDoc::openapi();

        let sboms = Arc::new(SbomRegistry::new());
        let guac = Arc::new(guac::Guac::new(&self.run.guac_url, sboms.clone()));

        let search = Arc::new(search::configure(&self.run)?);

        HttpServer::new(move || {
            let cors = Cors::default()
                .send_wildcard()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);

            App::new()
                .wrap(Logger::default())
                .wrap(cors)
                .app_data(Data::new(sboms.clone()))
                .app_data(Data::new(package::TrustedContent::new(
                    guac.clone(),
                    sboms.clone(),
                    self.run.snyk.clone(),
                )))
                .app_data(Data::new(guac.clone()))
                .configure(package::configure())
                .configure(vulnerability::configure())
                .configure(index::configure())
                .configure(|config| search(config))
                .service(web::resource("/healthz").to(health))
                .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
        })
        .bind((self.run.bind, self.run.port))?
        .run()
        .await?;
        Ok(())
    }
}
