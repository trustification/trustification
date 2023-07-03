use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::{UseAsyncHandleDeps, UseAsyncState};

use crate::{
    components::{
        advisory::{AdvisoryResult, AdvisorySearch},
        common::PageHeading,
        simple_pagination::*,
    },
    hooks::use_pagination_state::*,
};

// FIXME: use a different API and representation

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct AdvisoryProps {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Advisory)]
pub fn advisory(props: &AdvisoryProps) -> Html {
    let search = use_state_eq(UseAsyncState::default);
    let callback = {
        let search = search.clone();
        Callback::from(
            move |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>| {
                search.set((*state).clone());
            },
        )
    };
    let query = props.query.clone();

    // Pagination
    let total = search.data().and_then(|d| d.total);
    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    html!(
        <>
            <PageHeading subtitle="Search security advisories">{"Advisories"}</PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection variant={PageSectionVariant::Default}>
                <AdvisorySearch {callback} {query} pagination={pagination_state.clone()}/>

                <AdvisoryResult state={(*search).clone()} />

                <SimplePagination
                    position={PaginationPosition::Bottom}
                    total_items={total}
                    page={pagination_state.page}
                    per_page={pagination_state.per_page}
                    on_page_change={pagination_state.on_page_change}
                    on_per_page_change={pagination_state.on_per_page_change}
                />
            </PageSection>
        </>
    )
}
