use humansize::{format_size, BINARY};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct SourceCodeProperties {
    pub source: Rc<String>,
}

#[function_component(SourceCode)]
pub fn source_code(props: &SourceCodeProperties) -> Html {
    html!(
        <CodeBlock>
            <CodeBlockCode> { &props.source } </CodeBlockCode>
        </CodeBlock>
    )
}

#[derive(PartialEq, Properties)]
pub struct UnknownContentProperties {
    pub source: Rc<String>,
}

#[function_component(UnknownContent)]
pub fn unknown_content(props: &UnknownContentProperties) -> Html {
    html! (
        <Tabs>
            <Tab label="Overview">
                <Grid gutter=true>
                    <GridItem cols={[2]}>
                        <Technical size={props.source.as_bytes().len()}/>
                    </GridItem>
                </Grid>
            </Tab>
            <Tab label="Source">
                <SourceCode source={props.source.clone()} />
            </Tab>
        </Tabs>
    )
}

#[derive(PartialEq, Properties)]
pub struct TechnicalProperties {
    pub size: usize,
}

#[function_component(Technical)]
pub fn technical(props: &TechnicalProperties) -> Html {
    let title = html!(<Title>{"Statistics"}</Title>);
    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Size">{ format_size(props.size, BINARY) }</DescriptionGroup>
                </DescriptionList>
            </CardBody>
        </Card>
    )
}
