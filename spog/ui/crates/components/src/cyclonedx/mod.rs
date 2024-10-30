mod packages;

use std::collections::BTreeMap;
use std::rc::Rc;

pub use packages::*;

use patternfly_yew::prelude::*;
use serde_json::Value;
use spog_ui_common::utils::OrNone;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CycloneDXMetaProperties {
    pub bom: Rc<cyclonedx_bom::prelude::Bom>,
    pub source: Rc<String>,
}

#[function_component(CycloneDXMeta)]
pub fn cyclonedx_meta(props: &CycloneDXMetaProperties) -> Html {
    let spec_version = use_memo(props.source.clone(), |source| {
        serde_json::from_str::<Value>(source).ok().and_then(|json| {
            json.get("specVersion")
                .and_then(|spec_version| spec_version.as_str())
                .map(|val| val.to_string())
        })
    });

    let name = props
        .bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .map(|c| c.name.to_string());
    let version = props
        .bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .map(|c| c.version.as_ref().map(|e| e.to_string()).unwrap_or_default());
    let serial_number = props.bom.serial_number.as_ref().map(|s| s.to_string());

    html!(
        <Card full_height=true>
            <CardTitle><Title size={Size::XLarge}>{"Metadata"}</Title></CardTitle>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Name">{name}</DescriptionGroup>
                    <DescriptionGroup term="Version">{version}</DescriptionGroup>
                    <DescriptionGroup term="CycloneDX Version">{spec_version.as_ref().clone()}</DescriptionGroup>
                    <DescriptionGroup term="Serial Number">{serial_number}</DescriptionGroup>
                </DescriptionList>
            </CardBody>
        </Card>
    )
}

pub fn cyclonedx_creator(bom: &cyclonedx_bom::prelude::Bom) -> Html {
    let created = bom
        .metadata
        .as_ref()
        .and_then(|m| m.timestamp.as_ref())
        .map(|t| t.to_string());

    html!(
        <Card  full_height=true>
            <CardTitle><Title size={Size::XLarge}>{"Creation"}</Title></CardTitle>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Created">{created}</DescriptionGroup>
                </DescriptionList>
            </CardBody>
        </Card>
    )
}

pub fn cyclonedx_main(bom: &cyclonedx_bom::prelude::Bom) -> Html {
    match bom.metadata.as_ref() {
        Some(metadata) => match metadata.component.as_ref() {
            Some(component) => {
                html!(
                    <Card>
                        <CardTitle><Title size={Size::XLarge}>{ "Package" }</Title></CardTitle>
                        <CardBody>
                            <DescriptionList>
                                <DescriptionGroup term="Name">{ component.name.to_string() }</DescriptionGroup>
                                <DescriptionGroup term="Version">{ OrNone(component.version.as_ref()) }</DescriptionGroup>
                                <DescriptionGroup term="Type">{ component.component_type.to_string() }</DescriptionGroup>
                                <DescriptionGroup term="External References"> { cyclonedx_external_references(component)} </DescriptionGroup>
                            </DescriptionList>
                        </CardBody>
                    </Card>
                )
            }
            None => html!(),
        },
        None => html!(),
    }
}

pub fn cyclonedx_external_references(component: &cyclonedx_bom::prelude::Component) -> Html {
    let mut external_references = BTreeMap::new();
    // since in SPDX SBOM both CPE and PURL are listed in the external references
    // for UX conistency among the UI, they are managed in the same way in Cyclone SBOM
    if let Some(cpe) = component.cpe.as_ref() {
        external_references.insert(cpe.to_string(), "CPE".to_string());
    }
    if let Some(purl) = component.purl.as_ref() {
        external_references.insert(purl.to_string(), "PURL".to_string());
    }
    if let Some(ext_refs) = component.external_references.as_ref() {
        ext_refs.0.iter().for_each(|e| {
            external_references.insert(e.url.to_string(), e.external_reference_type.to_string());
        })
    }
    html!(
        <List>
            { for external_references.iter()
                .map(|(value, label)| {
                    html_nested!( <ListItem>
                        {&value} { " " }
                        <Label label={format!("{}", label)} color={Color::Grey} />
                    </ListItem> )
                })
            }
        </List>
    )
}
