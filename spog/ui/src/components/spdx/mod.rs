mod packages;

pub use packages::*;

use crate::utils::OrNone;
use humansize::{format_size, BINARY};
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spdx_rs::models::{PackageInformation, SPDX};
use std::str::FromStr;
use yew::prelude::*;

/// get the PURL of a SPDX package information
pub fn get_purl(package: &PackageInformation) -> Option<PackageUrl<'static>> {
    package
        .external_reference
        .iter()
        .find(|p| p.reference_type == "purl")
        .and_then(|package| PackageUrl::from_str(&package.reference_locator).ok())
}

pub fn spdx_creator(bom: &SPDX) -> Html {
    let title = html!(<Title>{"Creation"}</Title>);

    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Created">{ &bom.document_creation_information.creation_info.created.to_string() }</DescriptionGroup>
                    if let Some(info) = &bom.document_creation_information.creation_info.license_list_version {
                        <DescriptionGroup term="License List Version">{ &info.to_string() }</DescriptionGroup>
                    }
                    {
                        match bom.document_creation_information.creation_info.creators.len() {
                            0 => html!(),
                            1 => {
                                // we can be sure to have one
                                html!(
                                    <DescriptionGroup term="Creator">
                                        { bom.document_creation_information.creation_info.creators[0].clone() }
                                    </DescriptionGroup>
                                )
                            },
                            _ => html! (
                                <DescriptionGroup term="Creators">
                                    <List>
                                        { for bom.document_creation_information.creation_info.creators.iter().map(Html::from) }
                                    </List>
                                </DescriptionGroup>
                            )
                        }
                    }
                </DescriptionList>
            </CardBody>
            { bom.document_creation_information.creation_info.creator_comment.as_ref().map(|comment|{
                html_nested!(<CardBody> { comment } </CardBody>)
            })}
        </Card>
    )
}

pub fn spdx_meta(bom: &SPDX) -> Html {
    let title = html!(<Title>{"Metadata"}</Title>);

    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Name">{ &bom.document_creation_information.document_name }</DescriptionGroup>
                    <DescriptionGroup term="ID">{ &bom.document_creation_information.spdx_identifier }</DescriptionGroup>
                    <DescriptionGroup term="Namespace">{ &bom.document_creation_information.spdx_document_namespace }</DescriptionGroup>
                    <DescriptionGroup term="SPDX Version">{ &bom.document_creation_information.spdx_version }</DescriptionGroup>
                    <DescriptionGroup term="Data License">{ &bom.document_creation_information.data_license }</DescriptionGroup>
                </DescriptionList>
            </CardBody>
            { bom.document_creation_information.document_comment.as_ref().map(|comment|{
                html_nested!(<CardBody> { comment } </CardBody>)
            })}
        </Card>
    )
}

pub fn spdx_main(bom: &SPDX) -> Html {
    bom.document_creation_information
        .document_describes
        .iter()
        .map(|desc| {
            let title = html!(<Title>{ "Package" }</Title>);

            let content = match bom
                .package_information
                .iter()
                .find(|p| &p.package_spdx_identifier == desc)
            {
                Some(package) => {
                    vec![html!(
                    <DescriptionList>
                        <DescriptionGroup term="Name">{ &package.package_name }</DescriptionGroup>
                        <DescriptionGroup term="Version">{ OrNone(package.package_version.as_ref()) }</DescriptionGroup>
                        <DescriptionGroup term="External References"> { spdx_external_references(package)} </DescriptionGroup>
                    </DescriptionList>
                )]
                },
                None => vec![
                    html!(
                            <CardBody>
                                <DescriptionList>
                                    <DescriptionGroup term="ID">{ &desc }</DescriptionGroup>
                                </DescriptionList>
                            </CardBody>

                    ),
                    html!(
                        <CardBody>
                            { "ID could not be found in document" }
                        </CardBody>
                    ),
                ],
            };

            html!(
                <Card {title}>
                    {
                        for content.into_iter()
                            .map(|content|html_nested!(<CardBody>{content}</CardBody>))
                    }
                </Card>
            )
        })
        .collect()
}

pub fn spdx_stats(size: usize, bom: &SPDX) -> Html {
    let title = html!(<Title>{"Statistics"}</Title>);
    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Size">{ format_size(size, BINARY) }</DescriptionGroup>
                    <DescriptionGroup term="Packages">{ format!("{}", bom.package_information.len()) }</DescriptionGroup>
                </DescriptionList>
            </CardBody>
        </Card>
    )
}

/// render the external packages
pub fn spdx_external_references(package: &PackageInformation) -> Html {
    html!(
        <List>
            { for package
                .external_reference
                .iter()
                .map(|e| {
                    html!( <>
                        {&e.reference_locator} { " " }
                        <Label label={format!("{:?}", e.reference_category)} color={Color::Blue} /> { " " }
                        <Label label={format!("{}", e.reference_type)} color={Color::Grey} />
                    </> )
                })
            }
        </List>
    )
}

pub fn spdx_package_list_entry(package: &PackageInformation) -> Html {
    match get_purl(package) {
        Some(purl) => html!(<code>{ purl }</code>),
        None => match &package.package_version {
            Some(version) => html!(
                <Tooltip text={version.clone()}>
                    { &package.package_name }
                </Tooltip>
            ),
            None => {
                html!(&package.package_name)
            }
        },
    }
}
