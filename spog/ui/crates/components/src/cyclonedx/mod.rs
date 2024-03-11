mod packages;

use std::rc::Rc;

pub use packages::*;

use patternfly_yew::prelude::*;
use serde_json::Value;
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
