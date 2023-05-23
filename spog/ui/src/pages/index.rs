use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    /*
    let router = use_router::<AppRoute>();

    let primary = Callback::from(move |_| {
        if let Some(router) = &router {
            router.push(AppRoute::Package {
                package: String::default(),
            });
        }
    })
    .into_action("Check package");

    let secondaries = vec![];
     */

    html!(
        <>
            <PageSection variant={PageSectionVariant::Light} fill=false>
                <Title level={Level::H1}>{"Trusted Content"}</Title>
                <Title level={Level::H2}>{"Fully hosted and managed service"}</Title>
                {"hi"}
            </PageSection>
            <PageSection variant={PageSectionVariant::Light} fill=true>
                <Grid gutter={true}>
                    <GridItem cols={WithBreakpoint::new(12)}>
                        <Card title={html!("Search")}>
                            {"Search!"}
                        </Card>
                    </GridItem>
                    <GridItem cols={WithBreakpoint::new(6)}>
                        <Card title={html!("Get Started")}>
                            {"Get Started"}
                        </Card>
                    </GridItem>
                    <GridItem cols={WithBreakpoint::new(6)} rows={WithBreakpoint::new(2)}>
                        <Card title={html!("Why Trust Red Hat?")}>
                            {"Why trust Red Hat?"}
                        </Card>
                    </GridItem>
                    <GridItem cols={WithBreakpoint::new(6)}>
                        <Card title={html!("Subscribe")}>
                            {"Subscribe"}
                        </Card>
                    </GridItem>
                </Grid>
            </PageSection>
        </>
    )
}
