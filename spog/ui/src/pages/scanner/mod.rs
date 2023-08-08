mod inspect;
// mod unknown;
mod report;
mod upload;

use anyhow::bail;
use bombastic_model::prelude::SBOM;
use inspect::Inspect;
use patternfly_yew::prelude::*;
use serde_json::Value;
use std::rc::Rc;
use upload::Upload;
use yew::prelude::*;

fn parse(data: &[u8]) -> Result<SBOM, anyhow::Error> {
    let sbom = SBOM::parse(data)?;

    #[allow(clippy::single_match)]
    match &sbom {
        SBOM::CycloneDX(_bom) => {
            // re-parse to check for the spec version
            let json = serde_json::from_slice::<Value>(data).ok();
            let spec_version = json.as_ref().and_then(|json| json["specVersion"].as_str());
            match spec_version {
                Some("1.3") => {}
                Some(other) => bail!("Unsupported CycloneDX version: {other}"),
                None => bail!("Unable to detect CycloneDX version"),
            }
        }
        _ => {}
    }

    Ok(sbom)
}

#[function_component(Scanner)]
pub fn scanner() -> Html {
    let content = use_state_eq(|| None::<Rc<String>>);
    let onsubmit = use_callback(|data, content| content.set(Some(data)), content.clone());

    let sbom = use_memo(
        |content| {
            content
                .as_ref()
                .and_then(|data| parse(data.as_bytes()).ok().map(|sbom| (data.clone(), Rc::new(sbom))))
        },
        content.clone(),
    );

    let onvalidate = use_callback(
        |data: Rc<String>, ()| match parse(data.as_bytes()) {
            Ok(_sbom) => Ok(data),
            Err(err) => Err(format!("Failed to parse SBOM as CycloneDX 1.3: {err}")),
        },
        (),
    );

    // allow resetting the form
    let onreset = use_callback(
        |_, content| {
            content.set(None);
        },
        content.clone(),
    );

    match &*sbom {
        Some((raw, _bom)) => {
            html!(<Inspect {onreset} raw={(*raw).clone()} />)
        }
        None => {
            html!(
                <>
                    <CommonHeader />
                    <PageSection variant={PageSectionVariant::Default} fill=true>
                        <Grid gutter=true>
                            <GridItem cols={[8]}>
                                <Card
                                    title={html!(<Title> {"SBOM content"} </Title>)}
                                >
                                    <CardBody>
                                        <Upload {onsubmit} {onvalidate}/>
                                    </CardBody>
                                </Card>
                            </GridItem>
                            <GridItem cols={[4]}>
                                <GenerateCard />
                            </GridItem>
                        </Grid>
                    </PageSection>
                </>
            )
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct CommonHeaderProperties {
    #[prop_or_default]
    pub onreset: Option<Callback<()>>,
}

#[function_component(CommonHeader)]
fn common_header(props: &CommonHeaderProperties) -> Html {
    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Inspect SBOM"}</Title>
                        <p>{ "Upload and analyze a custom SBOM" }</p>
                    </Content>
                </FlexItem>
                <FlexItem modifiers={[FlexModifier::Align(Alignment::Right), FlexModifier::Align(Alignment::End)]}>
                    if let Some(onreset) = &props.onreset {
                        <Button
                            label={"Scan another"}
                            icon={Icon::Redo}
                            variant={ButtonVariant::Secondary}
                            onclick={onreset.reform(|_|())}
                        />
                    }
                </FlexItem>
            </Flex>
        </PageSection>
    )
}

#[function_component(GenerateCard)]
fn generate_card() -> Html {
    let maven = r#"mvn org.cyclonedx:cyclonedx-maven-plugin:2.7.7:makeAggregateBom -Dcyclonedx.skipAttach=true -DoutputFormat=json -DschemaVersion=1.3 -Dcyclonedx.verbose=false"#;
    let container = r#"syft packages <container> -o cyclonedx-json --file sbom.json"#;
    let container_example = r#"syft packages quay.io/glassfish/server:5 -o cyclonedx-json --file sbom.json"#;

    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Container,
        Maven,
    }

    let selected = use_state_eq(|| TabIndex::Container);
    let onselect = use_callback(|index, selected| selected.set(index), selected.clone());

    html!(
        <Card
            title={html!(<Title>{"Generate"}</Title>)}
        >
            <CardBody>
                <Tabs<TabIndex> r#box=true selected={*selected} {onselect}>
                    <Tab<TabIndex> index={TabIndex::Container} title="Container">
                        <Content>
                            <p> { "Run the following command:" } </p>
                            <p> <TextInput readonly=true value={container}  /> </p>
                            <p> { "Be sure to replace " } <code> {"<container>"} </code> { "with the actual name of the container, for example:" } </p>
                            <p> <Clipboard readonly=true code=true value={container_example} variant={ClipboardVariant::Expanded} /> </p>
                            <p> { "The SBOM will be generated as: " } <code> { "target/sbom.json" } </code> </p>
                        </Content>
                    </Tab<TabIndex>>
                    <Tab<TabIndex> index={TabIndex::Maven} title="Maven">
                        <Content>
                            <p> { "Run the following command from the root of your project:" } </p>
                            <p> <Clipboard readonly=true code=true value={maven} variant={ClipboardVariant::Expanded} /> </p>
                            <p> { "The SBOM will be generated as: " } <code> { "sbom.json" } </code> </p>
                        </Content>
                    </Tab<TabIndex>>
                </Tabs<TabIndex>>
            </CardBody>
        </Card>
    )
}
