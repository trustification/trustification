use patternfly_yew::prelude::*;
use reqwest::Body;
use spog_ui_backend::{use_backend, AnalyzeService};
use spog_ui_common::error::components::Error;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

use crate::sbom::report::Report;

#[derive(Clone, PartialEq, Properties)]
pub struct ReportViewwerProperties {
    pub raw: Rc<String>,
}

#[function_component(ReportViewwer)]
pub fn report_viewer(props: &ReportViewwerProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let fetch = {
        use_async_with_cloned_deps(
            move |raw| async move {
                let service = AnalyzeService::new(backend, access_token);
                service.report(Body::from((*raw).clone())).await.map(Rc::new)
            },
            props.raw.clone(),
        )
    };

    html!(
        <>
            {
                match &*fetch {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        // <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        // </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(data)) => html!(
                        <Report data={data.clone()} />
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while generating report" />
                    )
                }
            }
        </>
    )
}
