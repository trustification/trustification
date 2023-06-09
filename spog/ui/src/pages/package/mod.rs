use crate::backend::{data::PackageRef, VexService};
use crate::components::{
    common::PageHeading,
    cvss::CvssScore,
    error::Error,
    package::{PackageResult, PackageSearch},
};
use crate::hooks::use_backend;
use crate::pages::AppRoute;
use csaf::Csaf;
use packageurl::PackageUrl;
use patternfly_yew::{
    next::{Card, CardBody, CardDivider},
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use std::str::FromStr;
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
    let query = props.query.clone();

    html!(
        <>
            <PageHeading subtitle="Search packages">{"Packages"}</PageHeading>

            // We need to set the main section to fill, as we have a footer section
            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>
                <PackageSearch {callback} {query} />
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
                            html!(<PackageResult {result} />)
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
