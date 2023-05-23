use crate::{backend::data::PackageRef, pages::AppRoute};
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use std::str::FromStr;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageVersionsProperties {
    pub versions: Vec<PackageRef>,
}

#[function_component(PackageVersions)]
pub fn package_versions(props: &PackageVersionsProperties) -> Html {
    #[derive(PartialEq)]
    struct PackageVersion<'a> {
        version: String,
        purl: PackageUrl<'a>,
        pkg: &'a PackageRef,
    }

    let mut versions = Vec::with_capacity(props.versions.len());
    for pkg in &props.versions {
        let purl = match PackageUrl::from_str(&pkg.purl) {
            Ok(purl) => purl,
            Err(_) => continue,
        };
        let version = match purl.version() {
            Some(version) => version.to_string(),
            None => continue,
        };
        versions.push(PackageVersion { version, purl, pkg });
    }

    // FIXME: do numeric version sorting
    versions.sort_unstable_by(|a, b| a.version.cmp(&b.version).reverse());

    html!(
        <List r#type={ListType::Plain}>
            {for versions.iter().map(|v|{
                html!(<>
                    <yew_nested_router::components::Link<AppRoute>
                        target={AppRoute::Package { package: v.purl.to_string() }}
                    >
                        {&v.version}
                    </yew_nested_router::components::Link<AppRoute>>
                </>)
            })}
        </List>
    )
}
