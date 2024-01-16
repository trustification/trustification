use crate::pages::ClickLearn;
use analytics_next::TrackingEvent;
use patternfly_yew::prelude::*;
use serde_json::json;
use spog_ui_components::editor::ReadonlyEditor;
use spog_ui_utils::{analytics::*, config::*, tracking_event};
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
        ("ScanSBOMPage File Loaded", json!({"numberOfFiles": value.0})).into()
    }
}

struct SubmitSbom {
    size: usize,
}

impl From<SubmitSbom> for TrackingEvent<'static> {
    fn from(value: SubmitSbom) -> Self {
        ("ScanSBOMPage ScanButton Clicked", json!({"size": value.size})).into()
    }
}

struct Dropped(&'static str, usize, usize);

impl From<Dropped> for TrackingEvent<'static> {
    fn from(value: Dropped) -> Self {
        (
            "ScanSBOMPage File Dropped",
            json!({
                "type": value.0,
                "items": value.1,
                "totalSize": value.2,
            }),
        )
            .into()
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

tracking_event!(Cleared: "ScanSBOMPage ClearButton Clicked" => json!({}));

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
    #[prop_or("Scan".into())]
    pub primary_btn_text: AttrValue,

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
                    analytics.track(Dropped(
                        "files",
                        files.len(),
                        files.iter().map(|f| f.size() as usize).sum(),
                    ));
                    drop_content.set(DropContent::Files(files));
                }))
            },
            ontext: {
                let drop_content = drop_content.clone();
                let analytics = analytics.clone();
                Some(Box::new(move |text, _data_transfer| {
                    analytics.track(Dropped("text", 1, text.len()));
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
        (drop_content.clone(), analytics.clone()),
        |_: MouseEvent, (drop_content, analytics)| {
            // clear state
            drop_content.set(DropContent::None);
            analytics.track(Cleared);
        },
    );

    let state = processing.error().map(
        |(_, err)| (InputState::Error, html_nested!(
            <HelperTextItem icon={HelperTextItemIcon::Visible} variant={HelperTextItemVariant::Error}> { err.clone() } </HelperTextItem>
        )),
    );
    let (state, helper_text) = match state {
        Some((state, helper_text)) => (Some(state), Some(helper_text)),
        None => (None, None),
    };
    let state = state.unwrap_or_default();

    let content = match &*processing {
        UseAsyncState::Ready(Ok(content)) => content.clone(),
        UseAsyncState::Ready(Err((content, _))) => content.clone(),
        _ => Default::default(),
    };

    use_effect_with((initial.clone(), content.clone()), |(initial, content)| {
        initial.set(content.is_empty());
    });

    let onsubmit = use_callback(
        (processing.clone(), props.onsubmit.clone(), analytics.clone()),
        |_: MouseEvent, (processing, onsubmit, analytics)| {
            if let Some(data) = processing.data() {
                analytics.track(SubmitSbom { size: data.len() });
                onsubmit.emit(data.clone());
            }
        },
    );

    let file_input_ref = use_node_ref();
    let onopen = use_callback(
        (file_input_ref.clone(), analytics.clone()),
        |_: (), (file_input_ref, analytics)| {
            analytics.track(("ScanSBOMPage LoadButton Clicked", None));
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlElement>() {
                ele.click();
            }
        },
    );
    let onopen_button = use_memo(onopen.clone(), |onopen| onopen.reform(|_: MouseEvent| ()));

    let onchange_open = use_callback(
        (file_input_ref.clone(), drop_content.clone(), analytics.clone()),
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
                ele.set_value("");
                drop_content.set(DropContent::Files(files));
            }
        },
    );

    let mut class = classes!("tc-c-drop-area");
    if *drop.over {
        class.push("pf-m-drag-over")
    }

    // build empty state actions

    let load_action = Action::new("Load an SBOM", onopen);
    let mut secondaries = vec![];

    let config = use_config();
    let onlearn = use_callback(config.scanner.documentation_url.clone(), |_, url| {
        if let Some(url) = &url {
            let _ = gloo_utils::window().open_with_url_and_target(url.as_ref(), "_blank");
        }
    });
    let onlearn = use_wrap_tracking(onlearn, (), |_, _| ClickLearn);

    if config.scanner.documentation_url.is_some() {
        secondaries.push(Action::new("Learn about creating an SBOM", onlearn));
    }

    let footer = html!(
        <Flex>
            <FlexItem>
                <Button
                    id="scanner-load"
                    disabled={processing.is_processing()}
                    variant={ButtonVariant::Secondary}
                    onclick={(*onopen_button).clone()}
                >
                    {"Load"}
                </Button>
            </FlexItem>
            <FlexItem>
                <Button
                    id="scanner-scan"
                    variant={ButtonVariant::Primary}
                    disabled={state == InputState::Error}
                    onclick={onsubmit}
                >
                    {&props.primary_btn_text}
                </Button>
            </FlexItem>
            <FlexItem>
                <Button
                    id="scanner-clear"
                    variant={ButtonVariant::Secondary}
                    disabled={drop_content.is_none()}
                    onclick={onclear}
                >
                    {"Clear"}
                </Button>
            </FlexItem>
            <FlexItem>
                if let Some(helper_text) = helper_text {
                    <HelperText id="scanner-help-text" live_region=true>
                        { helper_text }
                    </HelperText>
                }
            </FlexItem>
        </Flex>
    );

    // render

    html!(
        <>
            <Stack gutter=true>
                <StackItem fill=true>
                    <Card
                        full_height=true
                        plain=true
                        style="--pf-v5-c-card--BackgroundColor: var(--pf-v5-global--BackgroundColor--200);"
                        compact=true
                    >
                        <CardBody>
                            <div ref={node.clone()} {class} style="background-color: var(--pf-v5-global--BackgroundColor--100);">
                                <input ref={file_input_ref.clone()} style="display: none;" type="file" onchange={onchange_open} />
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
                            </div>
                        </CardBody>
                    </Card>
                </StackItem>
                <StackItem>
                    if !*initial {
                        {footer}
                    }
                </StackItem>
            </Stack>

        </>

    )
}
