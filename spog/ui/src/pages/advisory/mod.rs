use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::{UseAsyncHandleDeps, UseAsyncState};

use crate::components::{
    advisory::{AdvisoryResult, AdvisorySearch},
    async_state_renderer::AsyncStateRenderer,
    common::PageHeading,
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

    html!(
        <>
            <PageHeading subtitle="Search security advisories">{"Advisories"}</PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>
                <AdvisorySearch {callback} {query}/>

                <AsyncStateRenderer<AdvisorySummary>
                    state={(*search).clone()}
                    on_ready={Callback::from(move |result| {
                        html!(<AdvisoryResult {result} />)
                    })}
                />
            </PageSection>
        </>
    )
}
