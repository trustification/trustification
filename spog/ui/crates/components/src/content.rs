use crate::editor::ReadonlyEditor;
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
        <ReadonlyEditor content={props.source.clone()} />
    )
}

#[derive(PartialEq, Properties)]
pub struct UnknownContentProperties {
    pub source: Rc<String>,
}

#[function_component(UnknownContent)]
pub fn unknown_content(props: &UnknownContentProperties) -> Html {
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum UnknownTabs {
        Overview,
        Source,
    }

    let selected = use_state_eq(|| UnknownTabs::Overview);
    let onselect = use_callback(selected.clone(), |index, selected| selected.set(index));

    html! (
        <Tabs<UnknownTabs> selected={*selected} {onselect}>
            <Tab<UnknownTabs> index={UnknownTabs::Overview} title="Overview">
                <Grid gutter=true>
                    <GridItem cols={[2]}>
                        <Technical size={props.source.as_bytes().len()}/>
                    </GridItem>
                </Grid>
            </Tab<UnknownTabs>>
            <Tab<UnknownTabs> index={UnknownTabs::Source} title="Source">
                <SourceCode source={props.source.clone()} />
            </Tab<UnknownTabs>>
        </Tabs<UnknownTabs>>
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
