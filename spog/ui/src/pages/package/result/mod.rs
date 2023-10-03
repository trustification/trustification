mod tree;
mod versions;

use patternfly_yew::prelude::*;
use spog_ui_components::common::PageHeading;
use tree::Tree;
use versions::RelatedVersions;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    pub id: String,
}

#[function_component(ResultView)]
pub fn result_view(props: &ResultViewProperties) -> Html {
    html!(
        <>
            <PageHeading>{&props.id}</PageHeading>
            <PageSection>
                <Grid gutter=true>
                    <GridItem cols={[4]}>
                        <Card title={html!(<Title>{"Package versions discovered"}</Title>)}>
                            <CardBody>
                                <RelatedVersions package_id={props.id.clone()}/>
                            </CardBody>
                        </Card>
                    </GridItem>
                    <GridItem cols={[8]}>
                        <Card title={html!(<Title>{"Package dependents"}</Title>)}>
                            <CardBody>
                                <Tree package_id={props.id.clone()}/>
                            </CardBody>
                        </Card>
                    </GridItem>
                </Grid>
            </PageSection>
        </>
    )
}
