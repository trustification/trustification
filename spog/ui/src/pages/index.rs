use patternfly_yew::prelude::*;
use yew::prelude::*;

use crate::components::common::PageHeading;

#[function_component(Index)]
pub fn index() -> Html {
    html!(
        <>
            <PageHeading subtitle="Fully hosted and managed service" >{"Trusted Content"}</PageHeading>

            <PageSection variant={PageSectionVariant::Default} fill=true>
                <Grid gutter={true}>
                    <GridItem cols={[12.all()]}>
                        <Card title={html!("Search")}>
                            <CardBody>
                                {"Search!"}
                            </CardBody>
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]}>
                        <Card title={html!("Get Started")}>
                            <CardBody>
                                {"Get Started"}
                            </CardBody>
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]} rows={[2.lg(), 1.all()]}>
                        <Card title={html!("Why Trust Red Hat?")}>
                            <CardBody>
                                {"Why trust Red Hat?"}
                            </CardBody>
                        </Card>
                    </GridItem>
                    <GridItem cols={[6.lg(), 12.all()]}>
                        <Card title={html!("Subscribe")}>
                            <CardBody>
                                {"Subscribe"}
                            </CardBody>
                        </Card>
                    </GridItem>
                </Grid>
            </PageSection>

        </>
    )
}
