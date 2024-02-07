mod packages;

pub use packages::*;

use patternfly_yew::prelude::*;
use yew::prelude::*;

pub fn cyclonedx_meta(bom: &cyclonedx_bom::prelude::Bom) -> Html {
    let name = bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .map(|c| c.name.to_string());
    let version = bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .map(|c| c.version.to_string());
    let serial_number = bom.serial_number.as_ref().map(|s| s.to_string());

    html!(
        <Card full_height=true>
            <CardTitle><Title>{"Metadata"}</Title></CardTitle>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Name">{name}</DescriptionGroup>
                    <DescriptionGroup term="Version">{version}</DescriptionGroup>
                    <DescriptionGroup term="Serial number">{serial_number}</DescriptionGroup>
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
            <CardTitle><Title>{"Creation"}</Title></CardTitle>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Created">{created}</DescriptionGroup>
                </DescriptionList>
            </CardBody>
        </Card>
    )
}
