mod inspect;
mod unknown;
mod upload;

use crate::components::common::PageHeading;
use cyclonedx_bom::prelude::*;
use inspect::Inspect;
use patternfly_yew::prelude::*;
use std::rc::Rc;
use upload::Upload;
use yew::prelude::*;

#[function_component(Scanner)]
pub fn scanner() -> Html {
    let content = use_state_eq(|| None::<String>);

    let onsubmit = {
        let content = content.clone();
        Callback::from(move |data| {
            content.set(Some(data));
        })
    };

    let sbom = use_memo(
        |content| {
            content.as_ref().and_then(|data| {
                Bom::parse_from_json_v1_3(data.as_bytes())
                    .ok()
                    .map(|sbom| (Rc::new(data.clone()), Rc::new(sbom)))
            })
        },
        content.clone(),
    );

    match sbom.as_ref() {
        Some((raw, bom)) => {
            html!(<Inspect raw={raw.clone()} bom={bom.clone()} />)
        }
        None => {
            let onvalidate = Callback::from(|data: String| match Bom::parse_from_json_v1_3(data.as_bytes()) {
                Ok(_sbom) => Ok(data),
                Err(err) => Err(format!("Failed to parse SBOM: {err}")),
            });

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

#[function_component(CommonHeader)]
fn common_header() -> Html {
    html!(
        <PageHeading subtitle="Upload and analyze a custom SBOM">{"Inspect SBOM"}</PageHeading>
    )
}

#[function_component(GenerateCard)]
fn generate_card() -> Html {
    let maven = r#"mvn org.cyclonedx:cyclonedx-maven-plugin:2.7.7:makeAggregateBom -Dcyclonedx.skipAttach=true -DoutputFormat=json -DschemaVersion=1.3 -Dcyclonedx.verbose=false"#;
    let container = r#"syft packages <container> -o cyclonedx-json --file sbom.json"#;
    let container_example = r#"syft packages quay.io/keycloak/keycloak:latest -o cyclonedx-json --file sbom.json"#;

    html!(
        <Card
            title={html!(<Title>{"Generate"}</Title>)}
        >
            <CardBody>
                <Tabs r#box=true>
                    <Tab label="Container">
                        <Content>
                            <p> { "Run the following command:" } </p>
                            <p> <TextInput readonly=true value={container}  /> </p>
                            <p> { "Be sure to replace " } <code> {"<container>"} </code> { "with the actual name of the container, for example:" } </p>
                            <p> <Clipboard readonly=true code=true value={container_example} variant={ClipboardVariant::Expanded} /> </p>
                            <p> { "The SBOM will be generated as: " } <code> { "target/sbom.json" } </code> </p>
                        </Content>
                    </Tab>
                    <Tab label="Maven">
                        <Content>
                            <p> { "Run the following command from the root of your project:" } </p>
                            <p> <Clipboard readonly=true code=true value={maven} variant={ClipboardVariant::Expanded} /> </p>
                            <p> { "The SBOM will be generated as: " } <code> { "sbom.json" } </code> </p>
                        </Content>
                    </Tab>
                </Tabs>
            </CardBody>
        </Card>
    )
}
