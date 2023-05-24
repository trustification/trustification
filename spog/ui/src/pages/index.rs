use crate::components::common::PageHeading;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    html!(
        <>
            <PageHeading subtitle="Fully hosted and managed service" >{"Trusted Content"}</PageHeading>

            <PageSection variant={PageSectionVariant::Default} fill=true>
                <Grid gutter={true}>
                    <GridItem cols={[12.all()]}>
                        <Card title={html!("Search")}>
                            {"Search!"}
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]}>
                        <Card title={html!("Get Started")}>
                            {"Get Started"}
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]} rows={[2.lg(), 1.all()]}>
                        <Card title={html!("Why Trust Red Hat?")}>
                            {"Why trust Red Hat?"}
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]}>
                        <Card title={html!("Subscribe")}>
                            {"Subscribe"}
                        </Card>
                    </GridItem>
                </Grid>
            </PageSection>

        </>
    )
}
