use patternfly_yew::prelude::*;
use spog_ui_components::{common::PageHeading, cve::CveSearch};
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct CveProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(CveSearchPage)]
pub fn cve_search_page(props: &CveProperties) -> Html {
    let query = props.query.clone().filter(|s| !s.is_empty());

    html!(
        <>
            <PageHeading subtitle="Search for CVEs">{"CVE Catalog"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <CveSearch {query}/>
            </PageSection>
        </>
    )
}
