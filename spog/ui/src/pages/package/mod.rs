use std::rc::Rc;

use crate::components::{common::PageHeading, package::PackageResult, sbom::CatalogSearch};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageProps {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Package)]
pub fn package(props: &PackageProps) -> Html {
    let search = use_state_eq(UseAsyncState::default);
    let callback = {
        let search = search.clone();
        Callback::from(
            move |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>| {
                search.set((*state).clone());
            },
        )
    };
    let query = props.query.clone().filter(|s| !s.is_empty());

    html!(
        <>
            <PageHeading subtitle="Search for SBOMs">{"Package Catalog"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <CatalogSearch {callback} {query}>
                    <PackageResult state={(*search).clone()} />
                </CatalogSearch>
            </PageSection>
        </>
    )
}
