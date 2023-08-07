use std::rc::Rc;

use crate::components::{common::PageHeading, sbom::PackageResult, sbom::SbomSearch, search::*};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Package)]
pub fn package(props: &PackageProperties) -> Html {
    let search = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>, search| search.set((*state).clone()),
        search.clone(),
    );
    let query = props.query.clone().filter(|s| !s.is_empty());

    html!(
        <>
            <PageHeading subtitle="Search for SBOMs">{"SBOM Catalog"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <SbomSearch {callback} mode={SearchPropertiesMode::Managed {query}}>
                    <PackageResult state={(*search).clone()} />
                </SbomSearch>
            </PageSection>
        </>
    )
}
