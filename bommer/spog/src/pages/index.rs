use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    html!(
        <>
            <PageSection
                variant={PageSectionVariant::Light}
                shadow={PageSectionShadow::Bottom}
                fill=false
            >
                <Content>
                    <Title level={Level::H1}>{"Single Pane of Glass"}</Title>
                </Content>
            </PageSection>

            <PageSection variant={PageSectionVariant::Default} fill=true>
                <Bullseye>
                    <img src="assets/images/crystal-ball-svgrepo-com.svg" />
                </Bullseye>
            </PageSection>
        </>
    )
}
