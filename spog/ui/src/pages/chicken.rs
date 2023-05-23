use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Chicken)]
pub fn chicken() -> Html {
    html!(
        <>
            <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light} >
                <Content>
                    <Title size={Size::XXXXLarge}>{"Chickens"}</Title>
                    <p>{ "Bock, Bock!" }</p>
                </Content>
            </PageSection>

            // We need to set the main section to fill, as we have a footer section
            <PageSection fill={PageSectionFill::Fill}>
                <img src="assets/images/IMG_3484.png" />
            </PageSection>
        </>
    )
}
