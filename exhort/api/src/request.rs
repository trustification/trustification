use serde::Deserialize;

#[allow(unused)]
#[derive(Deserialize)]
pub struct Request {
    packages: Vec<PackageRef>,
}

#[allow(unused)]
#[derive(Deserialize)]
pub struct PackageRef {
    name: String,
    version: String,
}