use std::sync::Arc;

use crate::Run;
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub struct Server {
    run: Run,
}

#[derive(OpenApi)]
#[openapi(
       // paths(
       //     crate::advisory::search,
       //     crate::sbom::search,
       //     crate::vulnerability::search,
       // ),
        //components(
        //    schemas(package::Package, package::PackageList, package::PackageDependencies, package::PackageDependents, package::PackageRef, package::SnykData, package::VulnerabilityRef, vulnerability::Vulnerability)
        //),
        //tags(
        //    (name = "package", description = "Package query endpoints."),
        //    (name = "vulnerability", description = "Vulnerability query endpoints")
        //),
    )]
pub struct ApiDoc;

impl Server {
    pub fn new(run: Run) -> Self {
        Self { run }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let openapi = ApiDoc::openapi();

        let search = Arc::new(crate::search::configure(&self.run)?);

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
                //.configure(package::configure())
                //.configure(vulnerability::configure())
                .configure(|config| search(config))
                .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/openapi.json", openapi.clone()))
        })
        .bind((self.run.bind, self.run.port))?
        .run()
        .await?;
        Ok(())
    }
}
