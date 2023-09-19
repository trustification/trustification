use patternfly_yew::prelude::*;
use spog_ui_components::{common::PageHeading, sbom::SbomSearch};
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Package)]
pub fn package(props: &PackageProperties) -> Html {
    let query = props.query.clone().filter(|s| !s.is_empty());

    html!(
        <>
            <PageHeading subtitle="Search for SBOMs">{"SBOM Catalog"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <SbomSearch {query}/>
            </PageSection>
        </>
    )
}
