use super::{report::Report, CommonHeader};
use crate::{backend::AnalyzeService, components::error::Error, hooks::use_backend};
use patternfly_yew::prelude::*;
use reqwest::Body;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(Clone, PartialEq, Properties)]
pub struct InspectProperties {
    pub raw: Rc<String>,
}

#[function_component(Inspect)]
pub fn inspect(props: &InspectProperties) -> Html {
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Report,
        Raw,
    }

    let tab = use_state_eq(|| TabIndex::Report);
    let onselect = use_callback(|index, tab| tab.set(index), tab.clone());

    let backend = use_backend();
    let access_token = use_latest_access_token();

    let fetch = {
        use_async_with_cloned_deps(
            |raw| async move {
                let service = AnalyzeService::new(backend, access_token);
                service.report(Body::from((*raw).clone())).await.map(Rc::new)
            },
            props.raw.clone(),
        )
    };

    html!(
        <>
            <CommonHeader />
            {
                match &*fetch {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(data)) => html!(
                        <>
                            <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                                <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                                    <Tab<TabIndex> index={TabIndex::Report} title="Report" />
                                    <Tab<TabIndex> index={TabIndex::Raw} title="Raw SBOM"/>
                                </Tabs<TabIndex>>
                            </PageSection>

                            <PageSection hidden={*tab != TabIndex::Report} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                                <Report data={data.clone()} />
                            </PageSection>

                            <PageSection hidden={*tab != TabIndex::Raw} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                                <CodeBlock>
                                    <CodeBlockCode>
                                        { &props.raw }
                                    </CodeBlockCode>
                                </CodeBlock>
                           </PageSection>
                        </>
                    ),
                    UseAsyncState::Ready(Err(err)) => html!(<Error {err} />),
                }
            }
        </>
    )
}
