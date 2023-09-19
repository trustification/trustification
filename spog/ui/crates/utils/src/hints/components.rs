use crate::{analytics::use_analytics, hints::Hints};
use analytics_next::TrackingEvent;
use patternfly_yew::prelude::*;
use serde_json::json;
use spog_ui_common::components::SafeHtml;
use yew::prelude::*;
use yew_hooks::use_local_storage;

/// Track the hiding of a hint.
pub struct HideHint<'a>(&'a str);

impl<'a> From<HideHint<'a>> for TrackingEvent<'a> {
    fn from(value: HideHint) -> Self {
        (
            "Hide Hint",
            json!({
                "hint": value.0
            }),
        )
            .into()
    }
}

#[derive(PartialEq, Properties)]
pub struct HintProperties {
    pub hint_key: String,
    pub hint: spog_model::config::Hint,
}

#[function_component(Hint)]
pub fn hint(props: &HintProperties) -> Html {
    let analytics = use_analytics();

    let hint_state = use_local_storage::<bool>(Hints::ScannerWelcome.to_string());

    let hide = (*hint_state).unwrap_or_default();

    let onhide = use_callback(
        |_, (hint_state, analytics, hint_key)| {
            hint_state.set(true);
            analytics.track(HideHint(hint_key));
        },
        (hint_state.clone(), analytics, props.hint_key.clone()),
    );

    let title = html!(<SafeHtml html={props.hint.title.clone()} />);
    let actions = Some(html!(
        <Button onclick={onhide} variant={ButtonVariant::Plain}> { Icon::Times } </Button>
    ));

    html!(
        if !hide {
            <PageSection
                variant={PageSectionVariant::Light}
                r#type={PageSectionType::Breadcrumbs}
            >
                <Card {actions} {title}
                    style="--pf-v5-c-card--BackgroundColor: var(--pf-v5-global--BackgroundColor--200);"
                >
                    <CardBody>
                        <SafeHtml html={props.hint.body.clone()} />
                    </CardBody>
                </Card>
            </PageSection>
        }
    )
}
