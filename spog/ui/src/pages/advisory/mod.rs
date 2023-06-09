use crate::components::{advisory::AdvisoryResult, advisory::AdvisorySearch, common::PageHeading, error::Error};
use csaf::Csaf;
use patternfly_yew::prelude::*;
use spog_model::search::SearchResult;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::{UseAsyncHandleDeps, UseAsyncState};

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
        Callback::from(move |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<Csaf>>>, String>| {
            search.set((*state).clone());
        })
    };
    let query = props.query.clone();

    html!(
        <>
            <PageHeading subtitle="Search security advisories">{"Advisories"}</PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>
                <AdvisorySearch {callback} {query}/>

                {
                    match &*search {
                        UseAsyncState::Pending | UseAsyncState::Processing => { html!( <Bullseye><Spinner/></Bullseye> ) }
                        UseAsyncState::Ready(Ok(result)) if result.is_empty() => {
                            html!(
                                <Bullseye>
                                    <EmptyState
                                        title="No results"
                                        icon={Icon::Search}
                                    >
                                        { "Try a different search expression." }
                                    </EmptyState>
                                </Bullseye>
                            )
                        },
                        UseAsyncState::Ready(Ok(result)) => {
                            let result = result.clone();
                            html!(<AdvisoryResult {result} />)
                        },
                        UseAsyncState::Ready(Err(err)) => html!(
                            <Error err={err.clone()}/>
                        ),
                    }
                }
            </PageSection>
        </>
    )
}
