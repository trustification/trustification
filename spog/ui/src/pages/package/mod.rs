mod search;
mod versions;

use crate::{
    backend::{data, Backend, PackageService},
    components::{common::PageHeading, deps::PackageReferences, remote_content, remote_refs_count_title},
    hooks::use_backend,
    pages::AppRoute,
    utils::RenderOptional,
};
use packageurl::PackageUrl;
use patternfly_yew::{
    next::{Card, CardBody, CardBodyVariant, CardDivider},
    prelude::*,
};
use search::PackageSearch;
use std::rc::Rc;
use std::str::FromStr;
use versions::*;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageProperties {
    #[prop_or_default]
    pub package: String,
}

#[function_component(Package)]
pub fn package(props: &PackageProperties) -> Html {
    html!(
        <>
            <PageHeading subtitle="Get detailed package information">
            {
                match purl(&props.package) {
                    Some(purl) => package_title(purl),
                    None => "Search Packages".into(),
                }
            }
            </PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>
                if let Some(purl) = purl(&props.package) {
                    <PackageInformation {purl} />
                } else {
                    <PackageSearch />
                }
            </PageSection>
        </>
    )
}

fn package_title(purl: PackageUrl) -> Html {
    let mut title = vec![];
    Extend::extend(&mut title, purl.namespace());
    title.push(purl.name());
    Extend::extend(&mut title, purl.version());

    html!(
        <>
            { title.join(" : ") }
            {" "}
            <Label label={purl.ty().to_string()} color={Color::Blue}/>
        </>
    )
}

fn purl(package: &str) -> Option<PackageUrl<'static>> {
    if package.is_empty() {
        return None;
    }

    PackageUrl::from_str(package).ok()
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct PackageInformationProperties {
    purl: PackageUrl<'static>,
}

#[function_component(PackageInformation)]
fn package_information(props: &PackageInformationProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| PackageService::new((**backend).clone()), backend.clone());

    let fetch_package = {
        let service = service.clone();
        use_async_with_cloned_deps(|purl| async move { service.lookup(purl).await }, props.purl.clone())
    };

    let fetch_versions = {
        let service = service.clone();
        use_async_with_cloned_deps(
            |mut purl| {
                purl.without_version();
                async move { service.search(vec![purl]).await }
            },
            props.purl.clone(),
        )
    };

    let fetch_deps_out = {
        let service = service.clone();
        use_async_with_cloned_deps(
            |purl| async move { service.dependencies([purl]).await },
            props.purl.clone(),
        )
    };

    let fetch_deps_in = {
        let service = service.clone();
        use_async_with_cloned_deps(
            |purl| async move { service.dependents([purl]).await },
            props.purl.clone(),
        )
    };

    let pkg_name = match props.purl.namespace().clone() {
        Some(namespace) => html!(<> {namespace} {" : "} {props.purl.name()} </>),
        None => html!(props.purl.name()),
    };

    html!(
        <Grid gutter=true>
            <GridItem cols={[9]}>
                <Card compact=true>
                    <CardBody>
                        <Tabs>
                            <Tab label={remote_refs_count_title(&fetch_deps_out, |data|data.first(), "Dependency", "Dependencies")}>
                                { remote_content(&fetch_deps_out, |data| html!(
                                    <PackageReferences refs={data.first().cloned().map(|d|d.0).unwrap_or_default()} />
                                )) }
                            </Tab>

                            <Tab label={remote_refs_count_title(&fetch_deps_in, |data|data.first(), "Dependent", "Dependents")}>
                                { remote_content(&fetch_deps_in, |data| html!(
                                    <PackageReferences refs={data.first().cloned().map(|d|d.0).unwrap_or_default()} />
                                )) }
                            </Tab>

                            <Tab label={remote_refs_count_title(&fetch_package, |data|Some(&data.vulnerabilities), "Vulnerability", "Vulnerabilities")}>
                                { remote_content(&fetch_package, |data| html!(
                                    <PackageVulnerabilities package={data.clone()} />
                                )) }
                            </Tab>
                        </Tabs>
                    </CardBody>
                </Card>
            </GridItem>

            <GridItem cols={[3]}>
                <Gallery style="--pf-l-gallery--GridTemplateColumns--min: 500px;" gutter=true>

                    <Card
                        title={html!(<Title size={Size::XLarge}>{ pkg_name }</Title>)}
                    >
                        <CardBody>
                            <Clipboard readonly=true code=true value={props.purl.to_string()} />
                        </CardBody>
                        <CardBody>
                            <DescriptionList>
                                <DescriptionGroup term="Version">{props.purl.version().clone().or_none()}</DescriptionGroup>
                                if let Some(path) = props.purl.subpath() {
                                    <DescriptionGroup term="Path">{path}</DescriptionGroup>
                                }
                            </DescriptionList>
                        </CardBody>

                        { if !props.purl.qualifiers().is_empty() {
                            vec![
                                html_nested!(<CardDivider/>).into(),
                                html_nested!(
                                    <CardBody>
                                        <Title level={Level::H3}>{ "Qualifiers" }</Title>
                                        { for props.purl.qualifiers().iter().map(|(k, v)|{
                                            html!(<Label label={format!("{k}={v}")} />)
                                        })}
                                    </CardBody>
                                ).into()
                            ] as Vec<CardBodyVariant>
                        } else { vec![] }}
                    </Card>

                    { remote_card(&fetch_package, |_data|
                        html!(<>
                            {"Support"}
                        </>),
                    |data| html!( <>
                        <PackageDetails package={data.clone()}/>
                        <PackageVulnerabilities package={data.clone()}/>
                    </> )) }

                    { remote_card(&fetch_versions, |data|
                        remote_card_title_badge("Versions", data.map(|r|r.len())),
                    |data| html!(
                        <PackageVersions versions={data.0.clone()}/>
                    )) }

                </Gallery>
            </GridItem>
        </Grid>
    )
}

fn remote_card_title_badge(title: &str, entries: Option<usize>) -> Html {
    html!(<>
        {title}
        if let Some(entries) = entries {
            { " " } <Badge read=true> { entries } </Badge>
        }
    </>)
}

fn remote_card<T, E, FT, FB>(fetch: &UseAsyncState<T, E>, title: FT, body: FB) -> Html
where
    FT: FnOnce(Option<&T>) -> Html,
    FB: FnOnce(&T) -> Html,
    E: std::error::Error,
{
    let fetch = &*fetch;
    html!(
        <Card
            title={html!(<Title size={Size::XLarge}>
                { title(fetch.data()) }
            </Title>)}
        >
            <CardBody>
                { remote_content(fetch, body) }
            </CardBody>
        </Card>
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageDetailsProperties {
    pub package: data::Package,
}

#[function_component(PackageDetails)]
fn package_details(props: &PackageDetailsProperties) -> Html {
    let backend = use_context::<Rc<Backend>>().expect("Can only be called being wrapped by the 'Backend' component");

    log::info!("SBOM: {:?}", props.package.sbom);

    let sbom = props.package.sbom.as_ref().and_then(|href| backend.join(&href).ok());

    html!(
        if let Some(sbom) = sbom {
            <a
                class={classes!("pf-c-button", "pf-m-link", "pf-m-inline")}
                href={sbom.to_string()}
                download={""}
            >
                <span class={classes!("pf-c-button__icon", "pf-m-start")}>
                    { Icon::Download }
                </span>
                { "Download SBOM" }
            </a>
        }
    )
}

#[function_component(PackageVulnerabilities)]
fn package_details(props: &PackageDetailsProperties) -> Html {
    struct Vuln<'a> {
        cve: &'a str,
        // FIXME: try checking if we can add the severity
    }

    let vulns = props
        .package
        .vulnerabilities
        .iter()
        .map(|v| Vuln { cve: &v.cve })
        .collect::<Vec<_>>();

    html!(
        if !vulns.is_empty() {
            <Title level={Level::H3}>{ "Known vulnerabilities" } </Title>
            <List r#type={ListType::Plain}>
                {for vulns.into_iter().map(|v|{
                    html!(<>
                        <yew_nested_router::components::Link<AppRoute>
                            target={AppRoute::Vulnerability { cve: v.cve.to_string() }}
                        >
                            { &v.cve }
                        </yew_nested_router::components::Link<AppRoute>>
                    </>)
                })}
            </List>
        }
    )
}
