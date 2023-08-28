use crate::components::{advisory::AdvisorySearch, common::PageHeading};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct AdvisoryProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Advisory)]
pub fn advisory(props: &AdvisoryProperties) -> Html {
    let query = props.query.clone();

    html!(
        <>
            <PageHeading subtitle="Search security advisories">{"Advisories"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <AdvisorySearch {query} />
            </PageSection>
        </>
    )
}
