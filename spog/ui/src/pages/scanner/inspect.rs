use super::{report::Report, CommonHeader};
use analytics_next::TrackingEvent;
use patternfly_yew::prelude::*;
use reqwest::Body;
use serde_json::json;
use spog_ui_backend::{use_backend, AnalyzeService};
use spog_ui_common::error::components::ApiError;
use spog_ui_common::error::ApiErrorKind;
use spog_ui_components::editor::ReadonlyEditor;
use spog_ui_utils::analytics::use_analytics;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;
use yew_oauth2::hook::use_latest_access_token;

struct AnalyzeResult<'a>(&'a Result<Rc<String>, spog_ui_common::error::ApiError>);

impl<'a> From<AnalyzeResult<'a>> for TrackingEvent<'static> {
    fn from(value: AnalyzeResult<'a>) -> Self {
        (
            "ScanSBOMPage Scan Result",
            match &value.0 {
                Ok(value) => {
                    json!({"ok": {
                        "resultLen": value.len(),
                    }})
                }
                Err(err) => match &**err {
                    ApiErrorKind::Api { status, details } => json!({
                         "err": details.to_string(),
                         "status": status.as_u16(),
                    }),
                    _ => json!({
                        "err": err.to_string(),
                    }),
                },
            },
        )
            .into()
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct InspectProperties {
    pub raw: Rc<String>,
    pub onreset: Callback<()>,
}

#[function_component(Inspect)]
pub fn inspect(props: &InspectProperties) -> Html {
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Report,
        Raw,
    }

    let analytics = use_analytics();
    let tab = use_state_eq(|| TabIndex::Report);
    let onselect = use_callback(tab.clone(), |index, tab| tab.set(index));

    let backend = use_backend();
    let access_token = use_latest_access_token();

    let fetch = {
        use_async_with_cloned_deps(
            move |raw| async move {
                let service = AnalyzeService::new(backend, access_token);
                let result = service.report(Body::from((*raw).clone())).await.map(Rc::new);
                analytics.track(AnalyzeResult(&result));
                result
            },
            props.raw.clone(),
        )
    };

    html!(
        <>
            <CommonHeader onreset={props.onreset.clone()}/>
            {
                match &*fetch {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(state) => html!(
                        <>
                            <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                                <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                                    <Tab<TabIndex> index={TabIndex::Report} title="Report" />
                                    <Tab<TabIndex> index={TabIndex::Raw} title="Raw SBOM"/>
                                </Tabs<TabIndex>>
                            </PageSection>

                            <PageSection hidden={*tab != TabIndex::Report} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                                {
                                    match state {
                                        Ok(data) => html!(<Report data={data.clone()} />),
                                        Err(err) => html!(<ApiError title="Failed to process report" error={err.clone()} />),
                                    }
                                }
                            </PageSection>

                            <PageSection hidden={*tab != TabIndex::Raw} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                                <ReadonlyEditor content={props.raw.clone()} />
                           </PageSection>
                        </>
                    ),
                }
            }
        </>
    )
}
