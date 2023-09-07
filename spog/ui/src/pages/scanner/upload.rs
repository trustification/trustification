use crate::{
    analytics::{use_analytics, use_wrap_tracking},
    components::editor::ReadonlyEditor,
    hooks::use_config,
    pages::ClickLearn,
};
use analytics_next::TrackingEvent;
use patternfly_yew::prelude::*;
use serde_json::json;
use std::rc::Rc;
use wasm_bindgen_futures::JsFuture;
use yew::prelude::*;
use yew_hooks::prelude::*;
use yew_more_hooks::hooks::r#async::{UseAsyncState, *};

/// The content of the empty state body.
///
/// **NOTE**: This must be be valid HTML and wrapped with exactly one element.
const EMPTY_BODY_CONTENT: &str = r#"
<div>
    <p>Start by <strong>dragging and dropping a file here</strong> or clicking the <strong>Load an SBOM</strong> button. Red&nbsp;Hat does not store a copy of your SBOM.</p>
</div>
"#;

struct LoadFiles(u32);
impl From<LoadFiles> for TrackingEvent<'static> {
    fn from(value: LoadFiles) -> Self {
        ("Loading files", json!({"numerOfFiles": value.0})).into()
    }
}

struct SubmitSbom {
    size: usize,
}
impl From<SubmitSbom> for TrackingEvent<'static> {
    fn from(value: SubmitSbom) -> Self {
        ("Submit SBOM", json!({"size": value.size})).into()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum DropContent {
    None,
    Files(Vec<web_sys::File>),
    Text(Rc<String>),
}

impl From<String> for DropContent {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::None
        } else {
            Self::Text(Rc::new(value))
        }
    }
}

impl DropContent {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl std::fmt::Display for DropContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Files(files) => {
                for (n, name) in files.iter().map(|f| f.name()).enumerate() {
                    if n > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(&name)?;
                }
                Ok(())
            }
            Self::Text(_) => f.write_str("User Input"),
            Self::None => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct UploadProperties {
    pub onsubmit: Callback<Rc<String>>,
    #[prop_or(default_validate())]
    pub onvalidate: Callback<Rc<String>, Result<Rc<String>, String>>,
}

fn default_validate() -> Callback<Rc<String>, Result<Rc<String>, String>> {
    Callback::from(Ok)
}

#[function_component(Upload)]
pub fn upload(props: &UploadProperties) -> Html {
    let node = use_node_ref();

    let analytics = use_analytics();

    let initial = use_state_eq(|| true);

    let drop_content = use_state(|| DropContent::None);

    let drop = use_drop_with_options(
        node.clone(),
        UseDropOptions {
            onfiles: {
                let drop_content = drop_content.clone();
                let analytics = analytics.clone();
                Some(Box::new(move |files, _data_transfer| {
                    analytics.track((
                        "Dropped SBOM",
                        json!({
                            "type": "files",
                            "numberOfFiles": files.len(),
                        }),
                    ));

                    drop_content.set(DropContent::Files(files));
                }))
            },
            ontext: {
                let drop_content = drop_content.clone();
                let analytics = analytics.clone();
                Some(Box::new(move |text, _data_transfer| {
                    analytics.track((
                        "Dropped SBOM",
                        json!({
                            "type": "text",
                            "size": text.len()
                        }),
                    ));

                    drop_content.set(DropContent::from(text));
                }))
            },
            onuri: Some(Box::new(move |_uri, _data_transfer| {})),
            ..Default::default()
        },
    );

    let processing = use_async_with_cloned_deps(
        |(content, onvalidate)| async move {
            let content = match &*content {
                DropContent::Files(files) => {
                    let mut content = String::new();
                    for file in files {
                        match JsFuture::from(file.text()).await {
                            Ok(data) => content.push_str(&data.as_string().unwrap_or_default()),
                            Err(err) => {
                                return Err((
                                    Default::default(),
                                    format!(
                                        "Failed to receive content: {err}",
                                        err = err.as_string().unwrap_or_default()
                                    ),
                                ))
                            }
                        }
                    }
                    Rc::new(content)
                }
                DropContent::Text(text) => Rc::new(text.to_string()),
                DropContent::None => Default::default(),
            };

            if content.is_empty() {
                // return early if the content is empty
                Err((Default::default(), "Requires an SBOM".to_string()))
            } else {
                // return success, as validated JSON
                onvalidate.emit(content.clone()).map_err(|err| (content, err))
            }
        },
        (drop_content.clone(), props.onvalidate.clone()),
    );

    let onclear = use_callback(
        |_: MouseEvent, (drop_content, analytics)| {
            // clear state
            drop_content.set(DropContent::None);
            analytics.track("Cleared SBOM content");
        },
        (drop_content.clone(), analytics.clone()),
    );

    let state = processing.error().map(
        |(_, err)| (InputState::Error, err.clone(), html_nested!(
            <HelperTextItem icon={HelperTextItemIcon::Visible} variant={ HelperTextItemVariant::Error }> { err } </HelperTextItem>
        )),
    );
    let (state, error_reason, helper_text) = match state {
        Some((state, error_reason, helper_text)) => (Some(state), Some(error_reason), Some(helper_text)),
        None => (None, None, None),
    };
    let state = state.unwrap_or_default();

    use_effect_with_deps(
        |(analytics, reason, initial)| {
            if *initial {
                // we ignore any errors if the content is empty
                return;
            }
            if let Some(reason) = reason {
                analytics.track((
                    "SBOM parsing failed",
                    json!({
                        "reason": reason,
                    }),
                ));
            }
        },
        (analytics.clone(), error_reason.clone(), *initial),
    );

    let content = match &*processing {
        UseAsyncState::Ready(Ok(content)) => content.clone(),
        UseAsyncState::Ready(Err((content, _))) => content.clone(),
        _ => Default::default(),
    };

    use_effect_with_deps(
        |(initial, content)| {
            initial.set(content.is_empty());
        },
        (initial.clone(), content.clone()),
    );

    let onsubmit = use_callback(
        |_: MouseEvent, (processing, onsubmit, analytics)| {
            if let Some(data) = processing.data() {
                analytics.track(SubmitSbom { size: data.len() });
                onsubmit.emit(data.clone());
            }
        },
        (processing.clone(), props.onsubmit.clone(), analytics.clone()),
    );

    let file_input_ref = use_node_ref();
    let onopen = use_callback(
        |_: (), (file_input_ref, analytics)| {
            analytics.track(("Click load button", None));
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlElement>() {
                ele.click();
            }
        },
        (file_input_ref.clone(), analytics.clone()),
    );
    let onopen_button = use_memo(|onopen| onopen.reform(|_: MouseEvent| ()), onopen.clone());

    let onchange_open = use_callback(
        |_, (file_input_ref, drop_content, analytics)| {
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlInputElement>() {
                let files = ele
                    .files()
                    .map(|files| {
                        analytics.track(LoadFiles(files.length()));
                        let mut r = Vec::with_capacity(files.length().try_into().unwrap_or_default());
                        for i in 0..files.length() {
                            r.extend(files.get(i));
                        }
                        r
                    })
                    .unwrap_or_default();
                drop_content.set(DropContent::Files(files));
            }
        },
        (file_input_ref.clone(), drop_content.clone(), analytics.clone()),
    );

    let mut class = classes!("tc-c-drop-area");
    if *drop.over {
        class.push("pf-m-drag-over")
    }

    // build empty state actions

    let load_action = Action::new("Load an SBOM", onopen);
    let mut secondaries = vec![];

    let config = use_config();
    let onlearn = use_callback(
        |_, url| {
            if let Some(url) = &url {
                let _ = gloo_utils::window().open_with_url_and_target(url.as_ref(), "_blank");
            }
        },
        config.scanner.documentation_url.clone(),
    );
    let onlearn = use_wrap_tracking(onlearn, |_, _| ClickLearn, ());

    if config.scanner.documentation_url.is_some() {
        secondaries.push(Action::new("Learn about creating an SBOM", onlearn));
    }

    // render

    html!(
        <div ref={node.clone()} {class} style="background-color: var(--pf-v5-global--BackgroundColor--100);">
            <input ref={file_input_ref.clone()} style="display: none;" type="file" onchange={onchange_open} />
            <Stack gutter=true>
                <StackItem fill=true>
                    if *initial {
                        <EmptyState
                            title="Get started by loading your SBOM"
                            icon={Icon::Code}
                            size={Size::XXXXLarge}
                            primary={load_action}
                            {secondaries}
                            full_height=true
                        >
                            <Content>
                                { Html::from_html_unchecked(AttrValue::from(EMPTY_BODY_CONTENT)) }
                            </Content>
                        </EmptyState>
                    }
                    if !*initial {
                        <ReadonlyEditor content={content.clone()} />
                    }
                </StackItem>
                <StackItem>
                    if !*initial {
                        <Flex>
                            <FlexItem>
                                <Button
                                    disabled={processing.is_processing()}
                                    variant={ButtonVariant::Secondary}
                                    onclick={(*onopen_button).clone()}
                                >
                                    {"Load"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Button
                                    variant={ButtonVariant::Primary}
                                    disabled={state == InputState::Error}
                                    onclick={onsubmit}
                                >
                                    {"Scan"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Button
                                    variant={ButtonVariant::Secondary}
                                    disabled={drop_content.is_none()}
                                    onclick={onclear}
                                >
                                    {"Clear"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                if let Some(helper_text) = helper_text {
                                    <HelperText>
                                        { helper_text }
                                    </HelperText>
                                }
                            </FlexItem>
                        </Flex>
                    }
                </StackItem>
            </Stack>
        </div>
    )
}
