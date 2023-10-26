use patternfly_yew::prelude::*;
use spog_ui_components::{common::PageHeading, packages::PackagesSearch};
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(PackageSearchPage)]
pub fn cve_search_page(props: &PackageProperties) -> Html {
    let query = props.query.clone().filter(|s| !s.is_empty());

    html!(
        <>
            <PageHeading subtitle="Search for packages">{"Package Catalog"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <PackagesSearch {query}/>
            </PageSection>
        </>
    )
}
