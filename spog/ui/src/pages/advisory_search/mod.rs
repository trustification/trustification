use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::{UseAsyncHandleDeps, UseAsyncState};

use crate::components::{
    advisory::{AdvisoryResult, AdvisorySearch},
    common::PageHeading,
    search::*,
};

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct AdvisoryProperties {
    #[prop_or_default]
    pub query: Option<String>,
}

#[function_component(Advisory)]
pub fn advisory(props: &AdvisoryProperties) -> Html {
    let search = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>, search| {
            search.set((*state).clone())
        },
        search.clone(),
    );
    let query = props.query.clone();

    html!(
        <>
            <PageHeading subtitle="Search security advisories">{"Advisories"}</PageHeading>

            <PageSection variant={PageSectionVariant::Light}>
                <AdvisorySearch {callback} mode={SearchPropertiesMode::Managed {query}}>
                    <AdvisoryResult state={(*search).clone()} />
                </AdvisorySearch>
            </PageSection>
        </>
    )
}
