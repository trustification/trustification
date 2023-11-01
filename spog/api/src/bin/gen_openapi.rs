use spog_api::ApiDoc;
use std::fs;
use utoipa::OpenApi;

fn main() {
    let doc = ApiDoc::openapi().to_yaml().unwrap();
    fs::write("spog/api/schema/api.yaml", doc).unwrap();
}
