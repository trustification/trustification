use crate::components::common::PageHeading;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Chicken)]
pub fn chicken() -> Html {
    html!(
        <>
            <PageHeading subtitle="Bock, Bock!" >{"Chickens"}</PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection fill={PageSectionFill::Fill}>
                <img src="assets/images/IMG_3484.png" />
            </PageSection>
        </>
    )
}
